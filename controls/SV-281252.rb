control 'SV-281252' do
  title 'RHEL 10 must configure SELinux context type to allow the use of a nondefault faillock tally directory.'
  desc <<~DESC
    Not having the correct SELinux context on the faillock directory may lead to unauthorized access to the directory.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If the system does not have SELinux enabled and enforcing a targeted policy, or if the pam_faillock module is not configured for use, this requirement is not applicable.

    Verify RHEL 10 SELinux context type allows the use of a nondefault faillock tally directory.

    Verify the location of the nondefault tally directory for the pam_faillock module with the following command:

    $ sudo grep -w dir /etc/security/faillock.conf
    dir = /var/log/faillock

    Check the security context type of the nondefault tally directory with the following command:

    $ ls -Zd /var/log/faillock
    unconfined_u:object_r:faillog_t:s0 /var/log/faillock

    If the security context type of the nondefault tally directory is not "faillog_t", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to allow the use of a nondefault faillock tally directory while SELinux enforces a targeted policy.

    Enable the feature using the following command:

    $ sudo authselect enable-feature with-faillock

    Create a nondefault faillock tally directory (if it does not already exist) with the following example:

    $ sudo mkdir /var/log/faillock

    Add/modify the "/etc/security/faillock.conf" file to match the following line:

    dir = /var/log/faillock

    Update "/etc/selinux/targeted/contexts/files/file_contexts.local" with "faillog_t" context type for the nondefault faillock tally directory with the following command:

    $ sudo semanage fcontext -a -t faillog_t "/var/log/faillock(/.*)?"

    Update the context type of the nondefault faillock directory/subdirectories and files with the following command:

    $ sudo restorecon -R -v /var/log/faillock
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281252'
  tag rid: 'SV-281252r1166708_rule'
  tag stig_id: 'RHEL-10-700430'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-85718r1166707_fix'
  tag cci: ['CCI-000044']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -w dir /etc/security/faillock.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
