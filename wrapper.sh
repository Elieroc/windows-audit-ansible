#!/bin/bash

ANSIBLE_CALLBACK_PLUGINS="$PWD/callback_plugins" \
ANSIBLE_STDOUT_CALLBACK=concise_json \
ansible-playbook -i inventory.ini audit.yml
