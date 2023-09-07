#!/usr/bin/env python
# These are only needed if resalloc is enabled
import logging
import socket
from kobo.hub import models
from django.template.loader import render_to_string
import tempfile
import os
from resalloc.client import Connection as ResallocConnection
from osh.hub.scan.models import ResallocMapping
from django.core.exceptions import ObjectDoesNotExist
import time

from threading import Thread

from django.conf import settings

logger = logging.getLogger(__name__)

class ResallocWorker():
    @classmethod
    def get_hostname_from_ip(cls, ip_address):
        logger.debug("Getting hostname for {}".format(ip_address))
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname

    def wait_for_ssh(self):
        # TODO: How long shall we wait here?
        # TODO: If this functions gets killed before ticket is ready, it would leave the resalloc
        # ticket in `open` state forever. We should figure out a cleanup method for such tickets.
        while not self.ticket.ready:
            self.ticket.collect()
            if self.ticket.closed:
                logger.error("Ticket ID {} closed unexpectedly.".format(self.ticket.id))
                # TODO: Raise exception here
                return
            logger.debug("Waiting for ticket {}...".format(self.ticket.id))
            # TODO: Shall we use a better algorithm to wait here than linear wait?
            time.sleep(30)

        logger.debug("Ticket {} is ready.".format(self.ticket.id))

        # Could raise http.client.CannotSendRequest
        self.ip_address = self.ticket.wait().strip()

        logger.debug("Got IP Address {} for ticket {}".format(self.ip_address, self.ticket.id))

    def update_hostname_in_resalloc_mapping(self):
        # Worker name is same as hostname
        if not self.worker_name:
            hostname = self.get_hostname_from_ip(self.ip_address)
        else:
            hostname = self.worker_name
        logger.debug("Updated resalloc mapping for hostname {}".format(hostname))
        self.resalloc_mapping.hostname = hostname
        self.resalloc_mapping.save()

    def create_worker_in_kobo(self):
        self.kobo_worker = models.Worker.create_worker(self.worker_name)
        # Each virtual machine allocated through resalloc should get exactly one task
        # and it should be destroyed after that.
        self.kobo_worker.max_load = 1
        self.kobo_worker.arches.add(models.Arch.objects.get(name="noarch"))
        self.kobo_worker.channels.add(models.Channel.objects.get(name="default"))
        self.kobo_worker.save()
        logger.debug("Created kobo worker for hostname {}".format(self.worker_name))
        return self.kobo_worker

    def start_worker(self):
        # Generate /etc/osh/worker.conf through jinja template
        worker_conf = render_to_string("worker.conf.j2", {"OSH_HUB_URL":settings.OSH_HUB_URL, "OSH_WORKER_KEY": self.kobo_worker.worker_key})
        # Create a temporary file and save the template
        temporary_file = tempfile.NamedTemporaryFile()
        temporary_file.write(bytes(worker_conf.strip(), 'utf-8'))
        # Is this safe to assume this would always work?
        temporary_file.flush()
        # and transfer it to new worker.
        # Copy worker.conf to centos user's home directory
        # This requires the hub to have ssh access to the new worker
        logger.debug("scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 -i {} {} centos@{}:worker.conf".format(settings.RESALLOC_WORKER_SSH_PRIVATE_KEY, temporary_file.name, self.kobo_worker.name))
        scp_exit_status = os.system("scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 -i {} {} centos@{}:worker.conf".format(settings.RESALLOC_WORKER_SSH_PRIVATE_KEY, temporary_file.name, self.kobo_worker.name))
        try:
            if scp_exit_status != 0:
                logger.error("Failed to copy worker.conf to new worker {}".format(self.kobo_worker.name))
                return
        finally:
            # Delete the worker configs from hub
            temporary_file.close()
            # TODO: Shall we delete the worker here?

        logger.debug("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 -i {} centos@{} 'sudo mv worker.conf /etc/osh/worker.conf && sudo chown root:root /etc/osh/worker.conf'".format(settings.RESALLOC_WORKER_SSH_PRIVATE_KEY, self.kobo_worker.name))
        # /etc/osh/hub/id_rsa.worker
        move_worker_conf_status = os.system("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 -i {} centos@{} 'sudo mv worker.conf /etc/osh/worker.conf && sudo chown root:root /etc/osh/worker.conf'".format(settings.RESALLOC_WORKER_SSH_PRIVATE_KEY, self.kobo_worker.name))
        if move_worker_conf_status != 0:
            logger.error("Failed to move worker.conf to new worker {}".format(self.kobo_worker.name))
            # TODO: Shall we delete the worker here?
            return
        # Start the worker after this is finished
        logger.debug("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 -i {} centos@{} 'sudo systemctl restart osh-worker'".format(settings.RESALLOC_WORKER_SSH_PRIVATE_KEY, self.kobo_worker.name))
        start_worker_status = os.system("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 -i {} centos@{} 'sudo systemctl restart osh-worker'".format(settings.RESALLOC_WORKER_SSH_PRIVATE_KEY, self.kobo_worker.name))
        if start_worker_status != 0:
            logger.error("Failed to start worker worker at {}".format(self.kobo_worker.name))
            # TODO: Shall we delete the worker here?
            return


class ResallocWorkerFactory():
    poll_resalloc_workers_thread = None

    @classmethod
    def get_resalloc_connection(cls):
        #TODO: Verify that the connection is not broken here 
        # if not cls.connection:
        logger.debug("Creating new ResallocConnection ...")
        cls.connection = ResallocConnection(settings.RESALLOC_SERVER, request_survives_server_restart=True)
        return cls.connection

    @classmethod
    def get_resalloc_worker(cls, connection):
        resalloc_worker = ResallocWorker()
        resalloc_worker.ticket = connection.newTicket(settings.RESALLOC_WORKER_TAGS)
        logger.debug("Creating mapping for ticket {}".format(resalloc_worker.ticket.id))
        resalloc_worker.resalloc_mapping = ResallocMapping()
        resalloc_worker.resalloc_mapping.ticket_id = resalloc_worker.ticket.id
        resalloc_worker.resalloc_mapping.save()
        # connection.close()
        return resalloc_worker

    @classmethod
    def build_through_resalloc_worker(cls):
        # TODO: What would happen if this function gets killed midway?
        resalloc_worker = None
        connection = None
        try:
            connection = cls.get_resalloc_connection()
            resalloc_worker = cls.get_resalloc_worker(connection)
            # Wait for worker to come up
            resalloc_worker.wait_for_ssh()
            # Worker name should be set to hostname of the worker
            resalloc_worker.worker_name = resalloc_worker.get_hostname_from_ip(resalloc_worker.ip_address)
            resalloc_worker.update_hostname_in_resalloc_mapping()
            resalloc_worker.create_worker_in_kobo()
            resalloc_worker.start_worker()
            return
        except Exception:
            if resalloc_worker:
                resalloc_worker.resalloc_mapping.delete()
            resalloc_worker.ticket.close()
            if connection:
                connection.close()
            logger.debug("Failed to allocate worker.")

    @classmethod
    def start_new_workers(cls, number_of_workers):
        for i in range(number_of_workers):
            new_thread = Thread(target = ResallocWorkerFactory.build_through_resalloc_worker)
            new_thread.start()

    @classmethod
    def poll_resalloc_workers(cls):
        # TODO: At the beginning delete all resalloc mappings that do not have a hostname assigned
        # to them. Those were probably stale nodes that were never fully brought up. Also, close
        # their respective tickets. Probably add `setup_finished` field in mapping table, that 
        # could be used for this.
        while True:
            current_count = ResallocMapping.objects.count()
            missing_workers = settings.RESALLOC_WORKER_COUNT - current_count
            if missing_workers > 0:
                logger.debug("Starting {} new workers...".format(missing_workers))
                cls.start_new_workers(missing_workers)
            logger.debug("Sleeping for 30 seconds...")
            time.sleep(30)

    @classmethod
    def set_task_id_for_resalloc_mapping(cls, task_id):
        if settings.ENABLE_RESALLOC:
            task = models.Task.objects.get(id=task_id)
            try:
                resalloc_mapping = ResallocMapping.objects.get(hostname=task.worker.name)
            except ObjectDoesNotExist:
                # Only workers allocated through resalloc have a mapping entry for them.
                logger.debug("{} does not have a mapping for it".format(task.worker.name))
                return
            logger.debug("Updating resalloc mapping for {} ...".format(task.worker.name))
            resalloc_mapping.task_id = task_id
            resalloc_mapping.save()
            # Set the worker load to 0. This should avoid getting any new tasks assigned the worker.
            # Each worker allocated through resalloc should be destroyed once a task completes.
            task.worker.max_load = 0
            task.worker.save()
    
    @classmethod
    def delete_resalloc_worker(cls, task_id):
        if settings.ENABLE_RESALLOC:
            task = models.Task.objects.get(id=task_id)
            try:
                resalloc_mapping = ResallocMapping.objects.get(hostname=task.worker.name)
            except ObjectDoesNotExist:
                # Only workers allocated through resalloc have a mapping entry for them.
                logger.debug("{} does not have a mapping for it".format(task.worker.name))
                return
            logger.debug("Deleting worker for task id {}".format(task_id))
            connection = cls.get_resalloc_connection()
            ticket = connection.getTicket(str(resalloc_mapping.ticket_id))
            logger.debug("Deleting worker {}".format(task.worker.name))
            task.worker.delete()
            resalloc_mapping.delete()
            logger.debug("Closing ticket id {}".format(ticket.id))
            ticket.close()
            connection.close()

    @classmethod
    def start_poll_resalloc_workers_thread(cls):
        cls.poll_resalloc_workers_thread = Thread(target = ResallocWorkerFactory.poll_resalloc_workers)
        cls.poll_resalloc_workers_thread.start()

    @classmethod
    def check_poll_resalloc_workers_thread(cls):
        if not ResallocWorkerFactory.poll_resalloc_workers_thread or not cls.poll_resalloc_workers_thread.is_alive():
            logger.info("Trying to start ResallocWorkerFactory.poll_resalloc_workers_thread() thread...")
            cls.start_poll_resalloc_workers_thread()
        else:
            logger.debug("poll_resalloc_workers_thread is still running.")

# if settings.ENABLE_RESALLOC:
#         # Allocate worker through resalloc in a separate thread
#         ResallocWorkerFactory.check_poll_resalloc_workers_thread()
