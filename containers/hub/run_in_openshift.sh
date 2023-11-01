#!/bin/sh -x
#
for _ in $(seq 100); do
    pg_isready -h db && break
    sleep 0.5
done

# Migrations
# If the database is empty or if it has records about already
# applied migrations, this command should work without any troubles.
/usr/lib/python3.6/site-packages/osh/hub/manage.py migrate

# If the table of mock configs is empty, we most likely have an empty database.
# In this case, we load the initial data into the database to make the OSH
# hub work.
if [ "$(/usr/lib/python3.6/site-packages/osh/hub/manage.py dumpdata scan.MockConfig)" = "[]" ]; then
    /usr/lib/python3.6/site-packages/osh/hub/manage.py loaddata \
        osh/hub/{errata,scan}/fixtures/initial_data.json
fi


/usr/sbin/httpd -DFOREGROUND
