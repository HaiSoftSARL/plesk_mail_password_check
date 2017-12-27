#!/bin/bash
# Name: Mail Password Security
# Version: 2017-08-09
# Description: Check Plesk mailboxes for common security flaws
# Developer: Robin Labadie
# Websites: haisoft.fr | lrob.fr | terageek.org

##############
## Settings ##
##############

# Checks
check_length="on" # Is the password long enough or not
check_password_selfname="on" # Is the mail name the password or not
check_password_domain="on" # Is the domain name the password or not
check_password_simple="on" # Is the mail password too simple or not
check_password_charset="off" # Are characters in use too simple or not
password_charset_severity="2" # How many character types are needed 1-4

# Strengh
passwordlength="7"

##############
### Script ###
##############

# Misc Vars
selfname="MailPasswords"

# Download bash API
if [ ! -f "ultimate-bash-api.sh" ]; then
	wget https://raw.githubusercontent.com/UltimateByte/ultimate-bash-api/master/ultimate-bash-api.sh
	chmod +x ultimate-bash-api.sh
fi
source ultimate-bash-api.sh

# If Plesk auth view is found, then write all credentials into check_auth.txt
if [ -f "/usr/local/psa/admin/bin/mail_auth_view" ]; then
	fn_logecho "Writing password list"
	/usr/local/psa/admin/bin/mail_auth_view | grep "|" | tail -n +2 > check_auth.txt
else
	fn_logecho "[ERROR] Cannot find mail_auth_view from Plesk"
	exit 1
fi

# Analyzes result of the last test and takes action
fn_last_test_result(){
        if [ "${test}" == "fail" ]; then
		# Add reason to test result
		# No reason yet
		if [ -z "${reasons}" ]; then
			reasons="${reason}"
		else
		# Reasons already exist for the domain, add other ones
			reasons="${reasons} ; ${reason}"
		fi
	fi
}

# Check for password length according to $passwordlength
fn_check_password_length(){
if [ "${check_length}" == "on" ]; then
	if [ "${#mailpassword}" -lt "${passwordlength}" ]; then
		test="fail"
		reason="Password length is ${#mailpassword} chars for ${passwordlength} required"
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
		reason="Password is mail name"
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
                reason="Password is domain name"
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
		reason="Password is too easy"
	else
		test="pass"
	fi
	fn_last_test_result
fi
}

# Check if charset is rich enough
# NOT READY YET
fn_check_password_charset(){
passcharcomplexity=0
if [ "${check_password_charset}" == "on" ]; then
	# Check for lowercase chars
	if [[ "${mailpassword}" =~ [a-z] ]]; then
		passcharcomplexity=$((passcharcomplexity+1))
	fi
	# Check for uppercase chars
        if [[ "${mailpassword}" =~ [A-Z] ]]; then
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
	if [ "${passcharcomplexity} <= "${password_charset_severity}" ]; then
                test="fail"
                reason="Password is domain name"
        else
            	test="pass"
        fi
	fn_last_test_result
fi
}


# Run all the checks
fn_check_password_global(){
	unset reasons
	fn_check_password_length
	fn_check_password_selfname
	fn_check_password_domain
	fn_check_password_simple
	fn_check_password_charset
	if [ -n "${reasons}" ]; then
		error+=("[NOT SECURE] | ${mailaddress} | ${mailpassword} | ${reasons}")
		unsecuredcount=$((unsecuredcount+1))
		# List domain as problematic
		if [[ ! "${unsecureddomains[@]}" =~ "${maildomain}" ]]; then
			unsecureddomains+=( "${maildomain}" )
			unsecureddomainscount=$((unsecureddomainscount+1))
		fi
	fi
}

# Actually check for bad passwords
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
               	fn_check_password_global
        done <  <(cat check_auth.txt)
fi

echo ""

# Display unsecured mail addresses
if [ "${#error[@]}" == "0" ]; then
	fn_logecho "Unsecured email addresses:"
	for ((index=0; index < ${#error[@]}; index++)); do
		echo -en "${error[index]}\n"
	done
else
	fn_logecho "Congrats! All email addresses passwords are secured"
fi

for ((index=0; index < ${#unsecureddomains[@]}; index++)); do
	fn_logecho "Unsecured domain: ${unsecureddomains[index]}"
done

if [ -f "check_auth.txt" ];then
	rm -f check_auth.txt
fi
fn_logecho "Total addresses: ${totalmailaddresses}"
fn_logecho "Unsecured addresses: ${unsecuredcount}"
fn_logecho "Unsecured domains: ${unsecureddomainscount}"
fn_duration
