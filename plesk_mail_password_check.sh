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
check_password_charset="on"

# Strengh
passwordlength="4"

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

# If Plesk is installed, then write all credentials into check_auth.txt
if [ -f "/usr/local/psa/admin/bin/mail_auth_view" ]; then
	fn_logecho "Writing password list"
	/usr/local/psa/admin/bin/mail_auth_view | grep "|" | tail -n +2 > check_auth.txt
else
	fn_logecho "Cannot find mail_auth_view from Plesk, skipping writing password list"
fi

# Analyzes result of the last test and takes action
fn_last_test_result(){
        if [ "${test}" == "fail" ]; then
                error+=("[NOT SECURE] | ${mailaddress} | ${reason} | ${mailpassword}")
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
if [ "${check_password_selfname}" == "on" ];then
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
	maildomain="$(echo "${mailaddress}" | awk -F "@" '{print $2}')"
	maildomainonly="$(echo "${maildomain}" | awk -F "." '{print $1}')"
	mailext="$(echo "${maildomain}" | awk -F "." '{print $2}')"
	maildomainext="${maildomainonly}${mailext}"
        if [ "${mailpassword}" == "${maildomain}" ]||[ "${mailpassword}" == "${maildomainonly}" ]||[ "${mailpassword}" == "${maildomainext}" ]; then
                test="fail"
                reason="Password is domain name"
        else
            	test="pass"
        fi
	fn_last_test_result
fi
}
fn_check_password_charset(){
if [ "${check_password_charset}" ==on ]; then
        if [ "${mailpassword}"  ]; then
                test="fail"
                reason="Password is domain name"
        else
            	test="pass"
        fi
fi
}


# Run all the checks
fn_check_password_global(){
	fn_check_password_length
	fn_check_password_selfname
	fn_check_password_domain
}

# Check for bad passwords
if [ -f "check_auth.txt" ]; then
	while read -r line ; do
		mailaddress="$(echo "${line}" | awk '{print $2}')"
		mailpassword="$(echo "${line}" | awk '{print $5}')"
		fn_echo "Testing: ${mailaddress}"
		fn_check_password_global
	done <  <(cat check_auth.txt)
fi

echo ""

# Display errors
for ((index=0; index < ${#error[@]}; index++)); do
	echo -en "${error[index]}\n"
done

if [ -f "check_auth.txt" ];then
	rm -f check_auth.txt
fi
