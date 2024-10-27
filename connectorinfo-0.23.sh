#!/bin/bash
########################################################################################################
##
## connectorinfo.sh - SmartConnector troubleshooting tool.
## Author: Richard Hamitlon <richhamiltonat6@comcast.net>
## Verson: 0.23 Dueling Dunnocks
##
## Options:
## --------
##
##      -a Get agent data
##
##              Gather the contents of the agent data directory. The file (SmartConnector-Agent*.tar.gz) is written to /tmp.
##
##      -l Get logs
##
##              Gather the conents of the logs directory. The file (SmartConnector-Logs*.tar.gz) is written to /tmp.
##
##      -c List certificates
##
##              Uses arcsight agent keytool  to list the stored keys.
##
##      -h Help screen
##
##              Basic help screen.
##
##      -H Enhanced Help
##
##              View more detailed help information, usage, script dependancies and the change log.
##
##      -i Connector Info
##
##              Displays Connector/Parser version, type and count of fatal, errors, warnings, and info messages in logs.
##
##      -n Network informaton
##
##              Pulls network information from the connector host. This includes info from netstat,ifconfig, hostnamectl and netstat.
##
##      -o Operating system information
##
##              Consists of OS release information, memory information and ps aux output.
##
##      -O Operating system report
##
##              The report contains information about the host operating system found in all of the OS related command line options.
##
##              The OS report is written to the logs directory using the filename SmartConnector-OS-Report-{time stamp}.txt.
##
##      -p Process info for SmartConnectors
##
##              Pulls environment information and process information from SmartConnector process.
##
##      -R Connector Report
##
##              This report contains information about the connector configuration, process info
##              and log messages broken down by type. logStatus and checkStatus messages are included
##              as well. The remaining INFO messages aren't included. The log messages are extracted from
##              the agent.log file only. agent.out.wrapper.log info isn't included as of his release.
##
##              The connector report is written to the logs directory using the filename SmartConnector-Report-{time stamp}.txt
##
##      -s SSL properties
##
##              Pulls SSL information from the client.defaults.properties.
##
##      -S Connector Status report
##
##              Caputes the output from "arcsight -quiet agentcommand -c status"
##
##      -t Time/Date information
##
##              Retrieves connector host time and data information via timedatectl.
##
##      -v View log
##
##              View logs, config files and reports. The following files are available to review:
##
##              agent.log.*
##              agent.out.wrapper.log.*
##              ArcSight_SmartConnector_install.*.log
##              agent.properites
##              agent.wrapper.conf
##
##      -E Script Environment
##
##              See the exported envornment variables in script. Can be used for troubleshooting script issues.
##
##
## Usage:
## ------
##
##       Run this script from the SmartConnector home directory (i.e., /opt/arcsight/[connector_name]).
##
## Script dependancies
## -------------------
##
##      This script requires the following packages to be installed:
##
##              awk - Contains the awk command.
##              binutils - Contains strings.
##              coreutils - Contains cat and tr
##              findutils - Contians find.
##              firewalld - Contains firewalld and firewall-cmd.
##              grep - Contains grep and egrep.
##              gzip - Contains gzip.
##              iproute - Contains ip and ss.
##              less - Contains the less command.
##              nettools - Contains netstat and ifconfig.
##              procps-ng - Contains ps.
##              sed - Contains sed.
##              systemd - Contains systemctl, timedatectl and hostnamectl.
##              tar - Contains tar.
##
## Tested Operating Systems
##
##      CentOS 7.9, 8.4
##      Red Hat Enterprise Linux 8.5 
##      SUSE Linux Enterprise Server 15 Service Pack 3 
##
##      Connector info should work on Red Hat Enterprise Linux and derivatives.
##
##
## Changelog
## ---------
##
##      [0.1] - 05-25-2022
##
##      - Initial Release.
##
##      [0.11] - 06-02-2022
##
##      - Added Enhanced Help (-H option)
##      - Added Directory check at startup.
##      - Cleaned up code.
##      - Documented package dependancies in the enhanced help.
##      - Added command_check() to ensure the proper (or compatable) commands are used for compatibilty between RHEL/CentOS 7.x and above.
##      - Added support for ss in RHEL/CentOS 8.x and above.
##      - Added support for ip in RHEL/CentOS 8.x and above.
##      - Enhanced help cleanup.
##      - Added 'a' to the netstat/ss command.
##      - Removed dependancy on the strings command.
##      - Added connector_info(). See the enhanced help for details.
##
##      [0.12] - 06-10-2022
##
##      - Added report functionality (connector_report() and os_report()). 
##      - Rewrote connector_info() so it can be intergrated info the report function.
##      - Code clean up.
##      - Excluded *.hprof files from log archives.
##      - Modfied time stamp.
##      - All destinations are now listed in the connector info and report options.
##
##      [0.13] - 06-16-2022
##
##      - Rewrote view_log. Multiple files can be read from a menu.
##
##      [0.2] - 06-22-2022
##
##      - The connector report can now be generated using the selected agent.log.* file. 
##      - Modifed the report to include the selected agent.log file 
##      - Additional report and enhanced help cleanup. 
##      - Moved the script home to the bin directory. 
##      - Adjusted paths in the script to reflect the change.
## 
##      [0.21] - 06-23-2022
## 	
##      - Code clean up. 
##      - Report format fixes.
##      - Added SUSE Linux Enterprise Server 15 SP3 support (Should work with any SLES 15 release).
##        No planned support for SLES 11 since it EOLed back in 2019.
##      - Added Red Hat Enterprise 8.5 support (Should work with any RHEL 8.x release).
##
##      [0.22] - 06-29-2022
##      
##      - Added Remote Management information to the connector information. 
##      - Added FIPS status to the connector information.
##      - Added SELinux information.
##      - Added fapolicyd information.  
##      - Added fips OS status.
##      - timedate(), os_info() and  network_info() cleanup.  
##
##      [0.23] - 07-06-2022
##
##      - Added connector status check which consists of the output from "arcsight -quiet agentcommand -c status".
## TODO
## ----
##      - Depending on demand add a report for the wrapper log file.
##      - Add apparmour support for SLES. 
##
function agent_log_parser()
{
	local LOG_FILE="$1" 
        AGENT_LOG_REGEX='(\[[0-9]{4}-[0-9]{2}-[0-9]{2}\s[0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}\])(\[(FATAL|ERROR|WARN |INFO )\])(.*$)'
        AGENT_LOG_STATUS_REGEX="logStatus"
        AGENT_CHECK_STATUS_LINE_REGEX="checkStatusLine"

        FATALS=()
        ERRORS=()
        WARNINGS=()
        REPORT=()
        LOGSTATUS=()
        CHECKSTATUS=()
        OLDIFS=$IFS
	

	read -r -d '' -a AGENT_LOG < "$LOG_FILE"

        for I in "${AGENT_LOG[@]}"
        do

                [[ "$I" =~ ${AGENT_LOG_REGEX} ]]

                case ${BASH_REMATCH[2]} in

                        "[FATAL]")
                                FATALS+=($I)
                                ;;
                        
			"[ERROR]")
                                ERRORS+=($I)
                                ;;

                        "[WARN ]")
                                WARNINGS+=($I)
                                ;;

                        "[INFO ]")

                                if  [[ "$I" =~ $AGENT_LOG_STATUS_REGEX ]]
                                then
                                        LOGSTATUS+=($I)
                                fi

                                if [[ "$I" =~ $AGENT_CHECK_STATUS_LINE_REGEX ]]
                                then
                                        CHECKSTATUS+=($I)
                                fi
                                ;;
                esac
        done
        REPORT+=("Agent Log Information")
        REPORT+=($SEPERATOR)
        REPORT+=(" ")
	REPORT+=("Log file: $LOG_FILE")
	REPORT+=(" ")
        REPORT+=("Stats")
        REPORT+=("$DIVIDER")
        REPORT+=("FATALS: ${#FATALS[@]}")
        REPORT+=("ERRORS: ${#ERRORS[@]}")
        REPORT+=("WARNINGS: ${#WARNINGS[@]}")
        REPORT+=(" ")
        REPORT+=(" ")
        REPORT+=("LOG MESSAGES")
        REPORT+=($SEPERATOR)
        REPORT+=(" ")
        REPORT+=("FATALS")
        REPORT+=($DIVIDER)
        REPORT+=(" ")
        REPORT+=(${FATALS[@]})
        REPORT+=(" ")
        REPORT+=("ERRORS")
        REPORT+=($DIVIDER)
        REPORT+=(" ")
        REPORT+=(${ERRORS[@]})
        REPORT+=(" ")
        REPORT+=("WARNINGS")
        REPORT+=($DIVIDER)
        REPORT+=("")
	REPORT+=(${WARNINGS[@]})
        REPORT+=(" ")
        REPORT+=(" ")
        REPORT+=("STATE INFO")
        REPORT+=($SEPERATOR)
        REPORT+=(" ")
        REPORT+=("Log Status Lines")
        REPORT+=($DIVIDER)
        REPORT+=(" ")
        REPORT+=("${LOGSTATUS[@]}")
	REPORT+=(" ")
        REPORT+=("Check Status Lines")
        REPORT+=($DIVIDER)
        REPORT+=(" ")
        REPORT+=(${CHECKSTATUS[@]})
        REPORT+=(" ")
        REPORT+=(" ")
        printf "%s\n" "${REPORT[@]}"
        IFS=$OLDIFS
}

function arcsight_process_info()
{
	OLD_IFS=$IFS
	PIDS=()
	EXES=("${ARCSIGHT_HOME}bin/arcsight" "${ARCSIGHT_HOME}bin/scripts/execjava.sh" "${ARCSIGHT_HOME}jre/bin/java" "${ARCSIGHT_HOME}bin/wrapper/linux64/wrapper")
	PROCESS_INFO=()
	
		for BINARY in "${EXES[@]}"
                do
                        # IGNORE the "SC2016: Expressions don't expand in single quotes, use double quotes for that." message for line below.
                        ID=$("$ARCSIGHT_PS" aux | "$ARCSIGHT_GREP" "$BINARY" | "$ARCSIGHT_GREP" -v grep | "$ARCSIGHT_AWK" '{print $2}')
                        if [[ $ID =~ [0-9] ]];
                        then
                                PIDS+=($ID)
                        fi
                done
                if [ "${#PIDS[@]}" -eq 0 ]
                then
                        echo The SmartConnector is not running. Please start the SmartConnector
                fi

                IFS=$'\n'
		PROCESS_INFO+=("Connector Process Information")
                # echo "Connector Process Information"
                PROCESS_INFO+=("$SEPERATOR")
		# echo "$SEPERATOR"
                for (( ID=0; ID<=${#PIDS[ID]}-1;ID++ ))
                do
			PROCESS_INFO+=("")
			PROCESS_INFO+=(""Process ID ${PIDS[$ID]}"")
			PROCESS_INFO+=("$SEPERATOR")
                        PROCESS_INFO+=("")
			PROCESS_INFO+=("Command line:")
			PROCESS_INFO+=("$DIVIDER")
                        PROCESS_INFO+=("")
                        PROCESS_INFO+=("$("$ARCSIGHT_CAT" /proc/"${PIDS[$ID]}"/cmdline | "$ARCSIGHT_TR" '\0' '\n')")
			PROCESS_INFO+=("")
			PROCESS_INFO+=("Environment")
			PROCESS_INFO+=("$DIVIDER")
			PROCESS_INFO+=("")
                        PROCESS_INFO+=($("$ARCSIGHT_CAT" /proc/"${PIDS[$ID]}"/environ | "$ARCSIGHT_TR" '\0' '\n'))
			PROCESS_INFO+=("")
                done
		printf "%s\n" "${PROCESS_INFO[@]}" 
                IFS=$OLD_IFS			
}

function command_check()
{
        COMMANDS=("find" "awk" "cat" "firewalld" "grep" "egrep" "gzip" "hostnamectl" "ifconfig" "ip" "less" "netstat" "ps" "ss" "strings" "systemctl" "tar" "timedatectl" "tr" "uname" "sestatus" "fapolicyd" "aa-status" )
        for COMMAND in "${COMMANDS[@]}"
        do
                EXP=$(echo "$COMMAND" | tr '[:lower:]' '[:upper:]')
                IS_INSTALLED=$(which "$COMMAND" &>/dev/null && echo "INSTALLED" || echo "NOT")
                if [[ "$IS_INSTALLED" =~ INSTALLED ]]
                then
                        export "ARCSIGHT_""$EXP"=$(which "$COMMAND")
                fi
        done

        if [[ ! -v "${ARCSIGHT_IFCONFIG}" ]]
        then
                ARCSIGHT_IFCONFIG=$(which ip)
                export ARCSIGHT_IFCONFIG
        fi

        if [[ ! -v "{$ARCSIGHT_NETSTAT}" ]]
        then
                ARCSIGHT_NETSTAT=$(which ss)
                export ARCSIGHT_NETSTAT
        fi

        if [[ -v "ARCSIGHT_FIREWALLD" ]]
        then
                ARCSIGHT_FIREWALL_CMD=$(which firewall-cmd)
                export ARCSIGHT_FIREWALL_CMD
        fi
}

function connector_info()
{
        #
        # Parameters from agent.properties
        #
        PROPERTIES_DESTINATION_TYPE="(^agents\[*[0-9]\]\.destination\[*[0-9]\]\.type)=(.*$)"
        PROPERTIES_DESTINATION_PARMS="(^agents\[*[0-9]\]\.destination\[*[0-9]\]\.params)=(.*$)"
        PROPERTIES_AGENT_TYPE="(^agents\[*[0-9]\]\.type)=(.*$)"
        PROPERTIES_DESTINATION_COUNT="(^agents\[0\]\.destination\.count)=(.*$)"
	PROPERTIES_REMOTE_MANAGEMENT="(^remote\.management\.enabled)=(.*$)"
 	PROPERTIES_REMOTE_PORT="(^remote\.management\.listener\.port)=(.*$)"
        PROPERTIES_REMOTE_SECOND_PORT="(^remote\.management\.second\.listener\.port)=(.*)"
	PROPERTIES_FIPS="(^fips\.enabled)=(.*)"
	#
        # Parameters from agent.wrapper.conf
        #
        WRAPPER_JAVA_INIT_MEMORY_REGEX="(wrapper\.java.initmemory)=([0-9]*)"
        WRAPPER_JAVA_MAX_MEMORY_REGEX="(wrapper.java.maxmemory)=([0-9]*)"
        WRAPPER_DISPLAY_NAME="(wrapper.ntservice.displayname)=(.*$)"

        IS_FIPS="false"
	PROPERTIES=()

        OLDIFS=$IFS
        IFS=$'\n'

        read -r -d '' -a AGENT_PROPERTIES < "$ARCSIGHT_AGENT_PROPERTIES_FILE"
        read -r -d '' -a WRAPPER_CONF < "$ARCSIGHT_WRAPPER_CONF_FILE"
        
	for LINE in "${AGENT_PROPERTIES[@]}"
        do
                if [[ $LINE =~ $PROPERTIES_DESTINATION_TYPE ]];
                then
                        DESTINATION_TYPE+=("${BASH_REMATCH[2]}")
                fi

                if [[ $LINE =~ $PROPERTIES_DESTINATION_PARMS ]];
                then
                        DESTINATION_PARMS+=("${BASH_REMATCH[2]}")
                fi

                if [[ $LINE =~ $PROPERTIES_AGENT_TYPE ]];
                then
                        AGENT_TYPE=${BASH_REMATCH[2]}
                fi
                if [[ $LINE =~ $PROPERTIES_DESTINATION_COUNT ]]
                then
                        DESTINATION_COUNT=${BASH_REMATCH[2]}
                fi
		if [[ $LINE =~ $PROPERTIES_REMOTE_MANAGEMENT ]]
		then 
			IS_MANAGED=${BASH_REMATCH[2]}
		fi
		if [[ $LINE =~ $PROPERTIES_REMOTE_PORT ]]
		then
			PORT=${BASH_REMATCH[2]}
		fi
		if [[ $LINE =~ $PROPERTIES_REMOTE_SECOND_PORT ]]
		then
			SECOND_PORT=${BASH_REMATCH[2]}
		fi
		if [[ $LINE =~ $PROPERTIES_FIPS ]]
		then
			IS_FIPS=${BASH_REMATCH[2]}
		fi

        done

        for LINE in "${WRAPPER_CONF[@]}"
        do

                if [[ $LINE =~ $WRAPPER_JAVA_INIT_MEMORY_REGEX ]];
                then
                        JAVA_INIT_MEMORY="${BASH_REMATCH[2]}MB"
                fi

                if [[ $LINE =~ $WRAPPER_JAVA_MAX_MEMORY_REGEX ]];
                then
                        JAVA_MAX_MEMORY="${BASH_REMATCH[2]}MB"
                fi

                # wrapper.ntservice.displayname is defined twice. Only need #2.
                if [[ $LINE =~ $WRAPPER_DISPLAY_NAME ]];
                then
                        DISPLAY_NAME="${BASH_REMATCH[2]}"
                fi
        done

        PROPERTIES+=("Connector Properties")
        PROPERTIES+=("$SEPERATOR")
        PROPERTIES+=(" ")	
	PROPERTIES+=("Destination Properties")
	PROPERTIES+=("$DIVIDER")
	PROPERTIES+=(" ")
        PROPERTIES+=("Connector Displayname: $DISPLAY_NAME")
        PROPERTIES+=("FIPS Enabled: $IS_FIPS")
	PROPERTIES+=("Remotely Managed: $IS_MANAGED")
	PROPERTIES+=("Remote Management Listener Port: $PORT")
	PROPERTIES+=("Second Management Listener Port: $SECOND_PORT") 
	PROPERTIES+=("Connector Type: $AGENT_TYPE")
        PROPERTIES+=("Connector Destination Count: $DESTINATION_COUNT")
        for (( i=0; i < DESTINATION_COUNT; i++));
        do
                PROPERTIES+=("Destination type: ${DESTINATION_TYPE[$i]}")
                PROPERTIES+=("Destination Parameters: ${DESTINATION_PARMS[$i]}")
        done
	PROPERTIES+=(" ")
        PROPERTIES+=("Java Memory")
        PROPERTIES+=("$DIVIDER")
        PROPERTIES+=(" ")
        PROPERTIES+=("Java Initial memory: $JAVA_INIT_MEMORY")
        PROPERTIES+=("Java Max memory: $JAVA_MAX_MEMORY")
        printf "%s\n" "${PROPERTIES[@]}" 
        
	IFS=$OLDIFS
}

function connector_report()
{ 	
	DATE_TIME_STAMP=$(date +"%m-%d-%Y-%H%M%S-%Z")
	ARCSIGHT_REPORT_FILE="${ARCSIGHT_LOG_DIR}/SmartConnector-Report-${DATE_TIME_STAMP}.txt" 
	local LOG_FILE="$1"
        OLDIFS=$IFS
        IFS=$'\n'
        if [ ! -f "$ARCSIGHT_REPORT_FILE" ]
        then
                touch "$ARCSIGHT_REPORT_FILE"
        fi
        printf "\n%s\n" "Writing Connector Report to $ARCSIGHT_REPORT_FILE"
        write_connector_report "Connector Report"
        write_connector_report "$SEPERATOR"
        write_connector_report " "
        write_connector_report "Report date: $DATE_TIME_STAMP"
        write_connector_report " "
        echo "Gathering Connector Information"
        connector_info >> "$ARCSIGHT_REPORT_FILE"
        ssl_properties >> "$ARCSIGHT_REPORT_FILE"
        echo "Reading and parsing log file"
        agent_log_parser "$LOG_FILE" >> "$ARCSIGHT_REPORT_FILE"
        write_connector_report " "
        arcsight_process_info >> "$ARCSIGHT_REPORT_FILE"
        write_connector_report " "
	echo "Connector report was written to $ARCSIGHT_REPORT_FILE"
	IFS=$OLDIFS
}

function connector_status_report ()
{
	printf "%s\n" "Running status check"
	STATUS_REPORT=( "Connector Status Report" "$SEPERATOR" )
	STATUS_REPORT+=("$("$ARCSIGHT_BIN_DIR"/arcsight -quiet agentcommand -c status)")
	printf "%s\n" "${STATUS_REPORT[@]}" >> "$ARCSIGHT_STATUS_REPORT"
	printf "Connector status report written to %s:\n" "$ARCSIGHT_STATUS_REPORT" 
}
function enhanced_help()
{
  "$ARCSIGHT_GREP" "^##" "$0" | sed -e 's/#//g' | less
}

function find_files()
{
	FILES=("$@")
	for (( FILE=0; FILE < "${#FILES[@]}"; FILE++))
	do
		find "$ARCSIGHT_HOME" -name "${FILES[$FILE]}"
	done
}

function help()
{
        echo "$SCRIPT_NAME" v. "$VERSION"
        echo
        echo Get connector information
        echo
        echo Options:
        echo
        echo "  -a Get agent data"
        echo "  -l Get logs"
        echo "  -c List certificates"
        echo "  -h Help this screen"
        echo "  -i Connector information"
        echo "  -n Network informaton"
        echo "  -o Operating system information"
        echo "  -p Process info for SmartConnectors"
        echo "  -s SSL properties"
        echo "  -t Time/Date information"
        echo "  -v View log"
        echo "  -E Environment check"
        echo "  -H Enhanced help"
        echo "  -O Operating system report"
        echo "  -R SmartConnector report"
        echo "  -S SmartConnector status check"
        echo
        echo "Run this script from the connector's bin directory."
        exit
}
function list_certificates()
{
	"$ARCSIGHT_BIN_DIR/"arcsight agent keytool -store agentcerts -list
}
function list_files()
{
	local FILES=("$@")
	local AGENT_FILES=()
	local AGENT_RE='agent.log($|.*)'
	if [[ "$opt" == "R" ]]
	then
		for (( FILE=0; FILE < "${#FILES[@]}"; FILE++ ))
		do
			if [[ ${FILES[$FILE]} =~ $AGENT_RE ]];
			then
				AGENT_FILES+=("${FILES[$FILE]}") 
			fi
		done
		unset FILES
		FILES=("${AGENT_FILES[@]}")
		unset AGENT_FILES
	fi
	
	MAX="${#FILES[@]}"
	((MAX=MAX-1))
	RE='^[0-9]+$'

	[[ $opt = "R" ]] && TITLE="Connector Report" || TITLE="View Log"

	while :
	do
		printf "\033c"
		echo "$TITLE"
		echo "----------------"
		echo
		for(( FILE=0; FILE < "${#FILES[@]}"; FILE++ ))
		do
			printf "%d %s\n" "$FILE" "${FILES[$FILE]}"
		done
		echo
		read -p "Select a file [0 - $MAX ('q' to exit)]: " PICK 
	
		if [[ "$PICK" =~ [Qq] ]]
		then 
			exit
		fi

		if  [[ ! "$PICK" =~ $RE ]] ||  [[ "$PICK" -lt 0 ]] || [[ "$PICK" -gt $MAX ]]
		then 
			echo Invalid Option
			read -p "Press a [ENTER] to continue"
			continue
		fi
		
		if [[ "$PICK" -ge 0 ]] && [[ "$PICK" -le $MAX ]] && [[ "$opt" == "v" ]]
		then
			view_file "${FILES[$PICK]}"
		fi
	
		if [[ "$PICK" -ge 0 ]] && [[ "$PICK" -le $MAX ]] && [[ "$opt" == "R" ]]
		then
			connector_report "${FILES[$PICK]}"
		fi
	
	done
}

function network_info()
{
        OLDIFS=$IFS
        IFS=$'\n'
        HOSTNAME=($($ARCSIGHT_HOSTNAMECTL))

        if [[ ! -z "${ARCSIGHT_IP}" ]]
        then
                INTERFACE_INFO=($($ARCSIGHT_IFCONFIG a))
        else
                INTERFACE_INFO=($($ARCSIGHT_IFCONFIG))
        fi

        FIREWALL_STATUS=$("$ARCSIGHT_SYSTEMCTL" is-active firewalld)
        NETSTAT_TLNP=( $("$ARCSIGHT_NETSTAT" -tnlap) )
        INFO_NETWORK+=("Network Information")
        INFO_NETWORK+=("$SEPERATOR")
        INFO_NETWORK+=(" ")
        INFO_NETWORK+=("Hostname")
        INFO_NETWORK+=("$DIVIDER")
        INFO_NETWORK+=(" ")
        INFO_NETWORK+=("${HOSTNAME[*]}")
        INFO_NETWORK+=(" ")
        INFO_NETWORK+=("Interfaces")
        INFO_NETWORK+=("$DIVIDER")
        INFO_NETWORK+=(" ")
        INFO_NETWORK+=("${INTERFACE_INFO[*]}")
        INFO_NETWORK+=(" ")
        INFO_NETWORK+=("Firewall")
        INFO_NETWORK+=("$DIVIDER")
        INFO_NETWORK+=(" ")
        INFO_NETWORK+=("Firewall status $FIREWALL_STATUS")
        INFO_NETWORK+=(" ")
        if [[ $FIREWALL_STATUS = "active" ]]; then

            FIREWALL=( $("$ARCSIGHT_FIREWALL_CMD" --list-all) )
            INFO_NETWORK+=("${FIREWALL[@]}")
        fi
        INFO_NETWORK+=("Port Information")
        INFO_NETWORK+=("$SEPERATOR")
        INFO_NETWORK+=(" ")
        INFO_NETWORK+=("${NETSTAT_TLNP[@]}")
		printf "%s\n" "${INFO_NETWORK[@]}"
        IFS=$OLD_IFS
}

function os_info()
{
        OLD_IFS=$IFS
        IFS=$'\n'
        OS_RELEASE=($("$ARCSIGHT_CAT" /etc/*release*))
        MEM_INFO=($("$ARCSIGHT_CAT" /proc/meminfo))
        KERNEL_VERSION=$("$ARCSIGHT_UNAME" -r)
        PS_INFO=($($ARCSIGHT_PS aux))
        FIPS=$(sysctl crypto.fips_enabled)
        INFO_OS=()
	INFO_OS+=("OS Release")
        INFO_OS+=("$DIVIDER")
        INFO_OS+=("")
        INFO_OS+=("${OS_RELEASE[@]}")
        INFO_OS+=("")
        INFO_OS+=("Kernel version: $KERNEL_VERSION")
        INFO_OS+=("")
        INFO_OS+=("Security Information")
        INFO_OS+=("$DIVIDER")
        if [ ! -z "{$ARCSIGHT_SESTATUS}" ]
        then
                INFO_OS+=("$ARCSIGHT_SESTATUS")
        else
                INFO_OS+=("SELinux is not installed")
        fi
        INFO_OS+=("")
        if [ -z "{$ARCSIGHT_SESTATUS}" ]
        then
                INFO_OS+=("$ARCSIGHT_SYSTEMCTL status policyd")
        else
                INFO_OS+=("Fapolicyd is not installed")
        fi
        INFO_OS+=("")
	INFO_OS+=("FIPS OS Status")
        INFO_OS+=("$DIVIDER")
        INFO_OS+=("")
        INFO_OS+=("$FIPS")
        INFO_OS+=("")
        INFO_OS+=("Memory information")
        INFO_OS+=("$DIVIDER")
        INFO_OS+=("")
        INFO_OS+=("${MEM_INFO[*]}")
        INFO_OS+=("")
        INFO_OS+=("System Process Information")
        INFO_OS+=("$DIVIDER")
        INFO_OS+=("")
	INFO_OS+=("${PS_INFO[@]}")
	printf "%s\n" "${INFO_OS[@]}"

        IFS=$OLD_IFS
}

function os_report()
{
        OLDIFS=$IFS
        IFS=$'\n'

        if [ ! -f "$ARCSIGHT_OS_REPORT_FILE" ]
        then
                touch "$ARCSIGHT_OS_REPORT_FILE"
        fi
        echo "Writing OS Report"
        write_os_report "Smart Connector OS Report"
        write_os_report "$SEPERATOR"
        write_os_report " "
        write_os_report "Report date: $DATE_TIME_STAMP"
        write_os_report " "
        os_info >> "$ARCSIGHT_OS_REPORT_FILE"
        write_os_report " "
        network_info >> "$ARCSIGHT_OS_REPORT_FILE"
        write_os_report " "
        timedate_info >> "$ARCSIGHT_OS_REPORT_FILE"
        write_os_report " "
        write_os_report " "
        echo "OS Report was written to $ARCSIGHT_OS_REPORT_FILE"
}

function ssl_properties()
{
        OLDIFS=$IFS
        IFS=$'\n'
        CLIENT_DEFAULTS_PROPERTIES+=("SSL Properties")
        CLIENT_DEFAULTS_PROPERTIES+=("$SEPERATOR")
        CLIENT_DEFAULTS_PROPERTIES+=(" ")
        CLIENT_DEFAULTS_PROPERTIES+=($($ARCSIGHT_EGREP -v '^#|^[[:space:]]*$' "$ARCSIGHT_CLIENT_DFAULT_PROPERTIES"))
        CLIENT_DEFAULTS_PROPERTIES+=(" ")
        CLIENT_DEFAULTS_PROPERTIES+=(" ")
	printf "%s\n" "${CLIENT_DEFAULTS_PROPERTIES[@]}"
        IFS=$OLDIFS 
}

function timedate_info()
{
        OLD_IFS=$IFS
        IFS=$'\n'
        TIMEDATE=($($ARCSIGHT_TIMEDATECTL))
	INFO_TIMEDATE=()
        INFO_TIMEDATE+=("Time Date Information")
        INFO_TIMEDATE+=("======================")
        INFO_TIMEDATE+=(" ")
        INFO_TIMEDATE+=("${TIMEDATE[*]}")
        INFO_TIMEDATE+=(" ")
	printf "%s\n" "${INFO_TIMEDATE[@]}"
        IFS=$OLD_IFS 
	
}

function view_file()
{
	less "$1"
}

function write_os_report()
{
	 printf "%s\n" "$1" >> "$ARCSIGHT_OS_REPORT_FILE"
}


function write_connector_report()
{
	printf "%s\n" "$1" >> "$ARCSIGHT_REPORT_FILE"
}
function retrieve_data()
{
	echo "Creating /tmp/$2$3.tar.gz"
	"$ARCSIGHT_TAR" --exclude '*.hprof' -cvzf /tmp/"$2$3".tar.gz "$1"
}

#
# script_environ()
#
# Displays the exported shell variables. Used for debugging
# Use the -E option to execute this function

function script_environ()
{
	export ARCSIGHT_HOME ARCSIGHT_CLIENT_DFAULT_PROPERTIES ARCSIGHT_AGENT_DIR  ALL_FILES DATE_TIME_STAMP PWD VERSION
	export -p 
}

# =============== Script Start ===============
ARG_COUNT=$#
DATE_TIME_STAMP=$(date +"%m-%d-%Y-%H%M%S-%Z")
ARCSIGHT_HOME=$(pwd|grep -o '^.*/')
ARCSIGHT_CLIENT_DFAULT_PROPERTIES="${ARCSIGHT_HOME}config/client.defaults.properties"
ARCSIGHT_WRAPPER_CONF_FILE=${ARCSIGHT_HOME}user/agent/agent.wrapper.conf
ARCSIGHT_AGENT_PROPERTIES_FILE=${ARCSIGHT_HOME}user/agent/agent.properties
ARCSIGHT_AGENT_DIR="${ARCSIGHT_HOME}user/agent"
ARCSIGHT_LOG_DIR="${ARCSIGHT_HOME}logs"
ARCSIGHT_BIN_DIR="${ARCSIGHT_HOME}bin"
ARCSIGHT_OS_REPORT_FILE="${ARCSIGHT_LOG_DIR}/SmartConnector-OS-Report-${DATE_TIME_STAMP}.txt"
ARCSIGHT_REPORT_FILE="${ARCSIGHT_LOG_DIR}/SmartConnector-Report-${DATE_TIME_STAMP}.txt"
ARCSIGHT_STATUS_REPORT="${ARCSIGHT_LOG_DIR}/SmartConnector-Status-Report-${DATE_TIME_STAMP}.txt"
ALL_FILES=( "SmartConnector-*Report*" "ArcSight_SmartConnector_Install*" "agent.properties" "client.defaults.properties" "agent.log*" "agent.out.wrapper.log*")
FOUND_FILES=($(find_files "${ALL_FILES[@]}"))
PWD=$(pwd)
SEPERATOR="=========================="
DIVIDER="--------------------------"
VERSION="0.23 Dueling Dunnocks"  

printf "\033c"

if [ "$ARG_COUNT" -eq 0 ]
then
	help
fi 

if [ "$PWD" != "$ARCSIGHT_BIN_DIR" ]
then
	echo "Execute script from the connector\'s bin directory $ARCSIGHT_BIN_DIR"
	exit
fi

command_check

while getopts "acEhHilnoOpRSstvz" opt; do
	case ${opt} in

		a)
			retrieve_data "$ARCSIGHT_AGENT_DIR" "SmartConnector-Agent-" "$DATE_TIME_STAMP"
			;;
		c)
			list_certificates
			;;
		E)
			script_environ
			;;
		h)
			help
			;;
		H)
			enhanced_help
			;;
		i)
			connector_info
			;;
		l)
			retrieve_data "$ARCSIGHT_LOG_DIR" "SmartConnector-Logs-" "$DATE_TIME_STAMP"
			;;
		n)
			network_info
			;;
		o)
			os_info
			;;
		O)
			os_report	
			;;
		p)
			arcsight_process_info
			;;
		R)
			# connector_report is now called by view_file 
			list_files "${FOUND_FILES[@]}"
			view_file "${PICKED_FILE}"
			;;
		s)
			ssl_properties
			;;
		S)
			connector_status_report
			;;
		t)
			timedate_info
			;;
		v)
			list_files "${FOUND_FILES[@]}"
			view_file  "$PICKED_FILE" 
			;;
		*)
			echo "Unknown Option"
			help
			;;
	esac
done

