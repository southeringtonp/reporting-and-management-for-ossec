#!/bin/bash
############################################################
# Query OSSEC for agent status
#
# This can be on the local server, or on a remote machine
# using SSH with public-key authentication
#
# Set $OSSEC_SERVER to empty for a local OSSEC installation,
# or set all of the remaining variables if querying via
# remote SSH command.
#
############################################################

OSSEC_SERVER=
OSSEC_USER=splunk
OSSEC_COMMAND="sudo /var/ossec/bin/agent_control -l"
SSH_KEY_FILE=


if [ "$OSSEC_SERVER" = "" ]
then
	# Easiest method - Splunk installed on OSSEC server
	$OSSEC_COMMAND | grep Name
else
	# Remote server, using SSH and sudo
	ssh $OSSEC_SERVER -l $OSSEC_USER -i $SSH_KEY_FILE $OSSEC_COMMAND | grep Name
fi

