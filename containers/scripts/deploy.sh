#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: Copyright contributors to the OpenScanHub project.

# shellcheck disable=1091
source containers/scripts/utils.sh

# podman-compose is currently unable to use profiles
# see: https://github.com/containers/podman-compose/issues/430
CONTAINERS=(
    db
    osh-hub
    osh-worker
)

if [ "$IS_LINUX" = 1 ]; then
    PROFILE=""
else
    PROFILE="--profile=full-dev"
fi
START='-d'
FORCE='false'

help() {
    set +x
    echo "Usage: $0 [--help|-h] [--clean] [--force|-f] [--full-dev|-F] [--no-start]"
    echo
    echo "Options:"
    echo "  --clean          Remove all containers and volumes"
    echo "  -f, --force      Force compose down"
    echo "  -F, --full-dev   Create a system-independent development environment"
    echo "  -h, --help       Show this message"
    echo "  --no-start       Do not start containers"
}

main() {
    set -ex

    test_build_env || exit "$?"

    prepare_deploy

    podman-compose -p osh up --build $START "${CONTAINERS[@]}"

    if [ "$START" = '-d' ]; then
        wait_for_container 'HUB'
    fi
}

#Tests the build environment
#
# Returns:
# 0 if everything is setup correctly, 1 there's a version mismatch, 2 if there are missing dependencies and 3 if there's an unknown error
test_build_env() (
    set +e
    # check that we are in the top-level diretory of our git repo
    test -d .git || return 3
    for f in compose.yaml containers/{hub/{Dockerfile,run.sh},{worker,client}.Dockerfile}; do
        test -f "$f" || {
            echo "Missing file: $f"
            return 3
        }
    done

    # test if *-compose is installed
    command -v podman-compose >/dev/null 2>&1
    test $? = 0 || {
        echo 'Missing compose command'
        return 2
    }

    return 0
)


prepare_deploy() {
    test_deploy_env || exit "$?"

    if [ "$IS_LINUX" = 1 ]; then
        LABEL='io.podman'
    else
        LABEL='com.docker'
    fi
    LABEL+='.compose.project=osh'

    mapfile -t running < <(podman ps $LABEL -q 2>/dev/null)

    if [[ ${#running[@]} -gt 0 ]] && [ "$FORCE" = false ]; then
        # shellcheck disable=2016
        echo 'One or more containers are already running under `compose`. Please use `compose down` to kill them.'
        exit 4
    fi

    if [ "$IS_LINUX" != 1 ]; then
        running=()
    fi
    podman-compose -p osh $PROFILE down "${running[@]}"
}


#Tests the deployment environment
#
# Returns:
# 0 if everything is setup correctly, 1 there's a version mismatch, 2 if there
# are missing dependencies and 3 if there's an unknown error
test_deploy_env() (
    set +e
    cd kobo || return 2
    git ls-remote https://github.com/release-engineering/kobo > /dev/null ||\
        git ls-remote https://github.com/frenzymadness/kobo > /dev/null ||\
        return 2
)


clean() {
    set -e

    eval podman-compose "$PROFILE" down -v
    CONTAINERS=$(podman ps -a | grep 'osh' | sed -e "s/[[:space:]]\{2,\}/,/g" | cut -d, -f1)
    echo "$CONTAINERS" | xargs podman rm -f
    IMAGES=$(shell podman images | grep 'osh' | sed -e "s/[[:space:]]\{2,\}/,/g" | cut -d, -f3)
    echo "$IMAGES" | xargs podman rmi -f
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean)
            clean
            exit "$?"
            ;;
        --force|-f)
            FORCE='true'
            shift
            ;;
        --full-dev|-F)
            CONTAINERS+=('osh-client')
            shift
            ;;
        --no-start)
            START='--no-start'
            shift
            ;;
        *)
            if [ -z "$1" ]; then
                shift
            else
                echo "Unknown option: $1"
                exit 22 # EINVAL
            fi
            ;;
    esac
done

main
