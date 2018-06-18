#!/bin/bash
# Name: Mail Password Security
# Version: 2017-12-27
# Description: Check Plesk mailboxes for common security flaws
# Developer: Robin Labadie
# Websites: haisoft.fr | lrob.fr | terageek.org

##############
## Settings ##
##############

# Sensitivity
global_risk_threshold="1" # Lower is less tolerant

# Checks
check_password_length="on" # Is the password long enough or not
password_length_required="8" # How many characters minimum should the password be
check_password_selfname="on" # Is the mail name the password or not
check_password_domain="on" # Is the domain name the password or not
check_password_simple="on" # Is the mail password too simple or not
check_password_charset="on" # Are characters in use too simple or not
password_charset_required="3" # How many character types are needed 1-5

# Output options
displaydomains="off" # Wether to display unsecured domains or not

##############
### Script ###
##############

# Check that the script is launched with elevated privileges
if [ "$(id -u)" != "0" ]; then
	fn_echo "[ERROR] This script must be run with elevated privileges"
	exit 1
fi

# Misc Vars
selfname="$(basename "$(readlink -f "${BASH_SOURCE[0]}")")"

# Download bash API
if [ ! -f "ultimate-bash-api.sh" ]; then
	wget https://raw.githubusercontent.com/UltimateByte/ultimate-bash-api/master/ultimate-bash-api.sh
	chmod +x ultimate-bash-api.sh
fi
# shellcheck disable=SC1091
source ultimate-bash-api.sh

fn_usage(){
	fn_echo "Usage: ./${selfname} [command]"
	fn_echo "Available commands:"
	fn_echo " * show - Show mailboxes with unsecured passwords"
	fn_echo " * warn - Send email to mailboxes with unsecured passwords"
}

# Check user input
# If nothing has been inputted
if [ -z "$1" ]; then
	# Info about script usage
	fn_usage
	exit 0
# If there is too much args
elif [ -n "$2" ]; then
	fn_echo "[ERROR] Too many arguments!"
	# Info about script usage
	fn_usage
	exit 1
else
	if [ "$1" == "show" ]||[ "$1" == "warn" ]; then
		command="$1"
	else
		fn_echo "[ERROR] Invalid command!"
		# Info about script usage
		fn_usage
		exit 1
	fi
fi

# Check for password length according to $password_length
fn_check_password_length(){
if [ "${check_password_length}" == "on" ]; then
	if [ "${#mailpassword}" -lt "${password_length_required}" ]; then
		test="fail"
		reason="only ${#mailpassword}/${password_length_required} chars"
		severity="$(( ${password_length_required}/${#mailpassword} ))"
	else
		test="pass"
	fi
	fn_last_test_result
fi
}

# Check for passwords being self name, example@domain.tld has example as a password
fn_check_password_selfname(){
if [ "${check_password_selfname}" == "on" ]; then
	mailname="$(echo "${mailaddress}" | awk -F "@" '{print $1}')"
	if [ "${mailname}" == "${mailpassword}" ]; then
		test="fail"
		reason="mail name"
		severity=10
	else
		test="pass"
	fi
	fn_last_test_result
fi
}

# Check for passwords being domain name, example domain@domain.tld has domain as a password
fn_check_password_domain(){
if [ "${check_password_domain}" == "on" ]; then
        if [ "${mailpassword}" == "${maildomain}" ]||[ "${mailpassword}" == "${maildomainonly}" ]||[ "${mailpassword}" == "${maildomainext}" ]; then
                test="fail"
                reason="domain"
		severity=10
        else
            	test="pass"
        fi
	fn_last_test_result
fi
}

# Check for too easy known passwords
fn_check_password_simple(){
if [ "${check_password_simple}" == "on" ]; then
	mailname="$(echo "${mailaddress}" | awk -F "@" '{print $1}')"
	easypasswordslist=( "azerty" "qwerty" "hello" "salut" "azerty123" "qwertyuiop" "azertyuiop" "google" "haisoft" "yahoo" "facebook" "microsoft" "qwerty123" "soleil" "mirage" "baseball" "dragon" "football" "monkey" "letmein" "111111" "mustang" "access" "shadow" "master" "superman" "696969" "123123" "batman" "trustno1" "1234" "12345" "123456" "1234567" "12345678" "123456789" "2017" "cacao" "banane" "fraise" "framboise" "bepo" "admin" "password" "motdepasse" "pompidou" "macron" "chirac" "1789" "asterix" "obelix" "tintin" "hobbit" "freudon" "wordpress" "joomla" )
	if [[ "${easypasswordslist[@]}" =~ "${mailpassword}" ]]; then
		test="fail"
		reason="an easy pattern"
		severity=9
	else
		test="pass"
	fi
	fn_last_test_result
fi
}

# Check if charset is rich enough
fn_check_password_charset(){
if [ "${check_password_charset}" == "on" ]; then
	passcharcomplexity=0
	# Check for lowercase chars
	if [[ "${mailpassword}" =~ [a-z] ]]; then
		passcharcomplexity=$((passcharcomplexity+1))
	fi
	# Check for uppercase chars
        if [[ "${mailpassword}" =~ [A-Z] ]]; then
		passcharcomplexity=$((passcharcomplexity+1))
	fi
	# Check for accentuated chars
        if [[ "${mailpassword}" =~ [À-Ÿà-ÿ] ]]; then
		passcharcomplexity=$((passcharcomplexity+1))
	fi
	# Check for digit chars
        if [[ "${mailpassword}" =~ [0-9] ]]; then
		passcharcomplexity=$((passcharcomplexity+1))
	fi
	# Check for signs
        if [[ "${mailpassword}" = *[^[:alnum:]]* ]]; then
		passcharcomplexity=$((passcharcomplexity+1))
	fi
	if [ "${passcharcomplexity}" -lt "${password_charset_required}" ]; then
                test="fail"
                reason="only ${passcharcomplexity}/${password_charset_required} char types"
		severity=$(( ${password_charset_required}*2/${passcharcomplexity} ))
        else
            	test="pass"
        fi
	fn_last_test_result
fi
}

# Analyzes result of the last test and registers the reason
fn_last_test_result(){
        if [ "${test}" == "fail" ]; then
		# Count risk total for the address according to severity
		risk=$((risk+severity))
		# Register risk if threshold is reached
		# Add reason to test result
		# No reason yet
		if [ -z "${reasons}" ]; then
			reasons="Password is: ${reason}"
		else
		# Reasons already exist for the domain, add other ones
			reasons="${reasons} ; ${reason}"
		fi
	fi
}

# Create a raw list of all addresses and passwords
fn_list_passwords(){
	# If Plesk auth view is found, then write all credentials into check_auth.txt
	if [ -f "/usr/local/psa/admin/bin/mail_auth_view" ]; then
		fn_logecho "Writing password list"
		/usr/local/psa/admin/bin/mail_auth_view | grep "|" | tail -n +2 > check_auth.txt
	else
		fn_logecho "[ERROR] Cannot find mail_auth_view from Plesk"
		exit 1
	fi
}

# Run all the checks
fn_all_checks(){
	unset test
	unset reasons
	risk=0
	fn_check_password_length
	fn_check_password_selfname
	fn_check_password_domain
	fn_check_password_simple
	fn_check_password_charset
	# If password is bad
	if [ "${risk}" -ge "${global_risk_threshold}" ]; then
		error+=( "${risk}" "${mailaddress}" "${mailpassword}" "${reasons}" )
		unsecuredcount=$((unsecuredcount+1))
		# List domain as problematic
		if [[ ! "${unsecureddomains[@]}" =~ "${maildomain}" ]]; then
			unsecureddomains+=( "${maildomain}" )
			unsecureddomainscount=$((unsecureddomainscount+1))
		fi
	fi
}

# Actually check for bad passwords
fn_run_checks(){
	if [ -f "check_auth.txt" ]; then
		echo ""
		fn_echo "Testing mail addresses..."
		echo ""
		totalmailaddresses=0
		unsecuredcount=0
		unsecureddomainscount=0
		# Loop through all mail address
		while read -r line ; do
			totalmailaddresses=$((totalmailaddresses+1))
			# Get mail address and password into variables
			mailaddress="$(echo "${line}" | awk '{print $2}')"
			mailpassword="$(echo "${line}" | awk -F "|" '{print $4}' | awk '{print $1}')"
			maildomain="$(echo "${mailaddress}" | awk -F "@" '{print $2}')"
			maildomainonly="$(echo "${maildomain}" | awk -F "." '{print $1}')"
			mailext="$(echo "${maildomain}" | awk -F "." '{print $2}')"
			maildomainext="${maildomainonly}${mailext}"
			echo -en "\e[1A"
			echo -e "\r\e[0K ${totalmailaddresses} - ${mailaddress}"
			fn_all_checks
		done <  <(cat check_auth.txt)
	fi
	echo ""
}

fn_display_results(){
	# Display unsecured mail addresses
	# No bad passwords
	if [ "${#error[@]}" == "0" ]; then
		fn_logecho "Congrats! All email addresses passwords are secured"
	else
		fn_logecho "Unsecured email addresses:"
		# error+=( "${risk}" "${mailaddress}" "${mailpassword}" "${reasons}" )
		for ((index=0; index < ${#error[@]}; index+=4)); do
			risk="${error[index]}"
			mailaddress="${error[index+1]}"
			mailpassword="${error[index+2]}"
			reasons="${error[index+3]}"
			echo -en "Risk: ${risk} | ${mailaddress} | ${mailpassword} | ${reasons}\n"
		done
		if [ "${displaydomains}" == "on" ]; then
		fn_logecho "Unsecured domains:"
			for ((index=0; index < ${#unsecureddomains[@]}; index++)); do
				fn_logecho "Unsecured domain: ${unsecureddomains[index]}"
			done
		fi
	fi

	if [ -f "check_auth.txt" ];then
		rm -f check_auth.txt
	fi
	fn_logecho "Total addresses: ${totalmailaddresses}"
	fn_logecho "Unsecured addresses: ${unsecuredcount} from ${unsecureddomainscount} domains"
}

# Run script according to command
if [ "${command}" == "show" ]; then
	fn_list_passwords
	fn_run_checks
	fn_display_results
elif [ "${command}" == "warn" ];then
	fn_logecho "Sorry, warn command is not really available yet."
	exit 0
fi

fn_duration
