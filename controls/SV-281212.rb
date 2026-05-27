control 'SV-281212' do
  title 'RHEL 10 must configure the use of the pam_faillock.so module in the "/etc/pam.d/system-auth" file.'
  desc <<~DESC
    If the pam_faillock.so module is not loaded, the system will not correctly lock out accounts to prevent password guessing attacks.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 includes the use of the pam_faillock.so module in the "/etc/pam.d/system-auth" file:

    $ sudo grep pam_faillock.so /etc/pam.d/system-auth
    auth required pam_faillock.so preauth
    auth required pam_faillock.so authfail
    account required pam_faillock.so

    If the pam_faillock.so module is not present in the "/etc/pam.d/system-auth" file with the "preauth" line listed before pam_unix.so, this is a finding.

    If the system administrator can demonstrate that the required configuration is contained in a PAM configuration file included or substacked from the "system-auth" file, this is not a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to include the use of the pam_faillock.so module in the "/etc/pam.d/system-auth" file.

    If PAM is managed with authselect, enable the feature with the following command:

    $ sudo authselect enable-feature with-faillock

    Otherwise, add/modify the appropriate sections of the "/etc/pam.d/system-auth" file to match the following lines:

    Note: The "preauth" line must be listed before pam_unix.so.

    auth required pam_faillock.so preauth
    auth required pam_faillock.so authfail
    account required pam_faillock.so
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281212'
  tag rid: 'SV-281212r1166588_rule'
  tag stig_id: 'RHEL-10-600600'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-85678r1166587_fix'
  tag cci: ['CCI-000044']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep pam_faillock.so /etc/pam.d/system-auth") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
