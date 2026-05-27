control 'SV-281249' do
  title 'RHEL 10 must enable the SELinux targeted policy.'
  desc <<~DESC
    Setting the SELinux policy to "targeted" or a more specialized policy ensures the system will confine processes that are likely to be targeted for exploitation, such as network or system services.

    Note: During the development or debugging of SELinux modules, it is common to temporarily place nonproduction systems in "permissive" mode. In such temporary cases, SELinux policies should be developed, and once work is completed, the system should be reconfigured to "targeted".
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 SELINUX is using the targeted policy with the following command:

    $ sestatus | grep policy
    Loaded policy name:             targeted

    If the loaded policy name is not "targeted", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to use the targeted SELINUX policy.

    Edit the file "/etc/selinux/config" and add or modify the following line:

    SELINUXTYPE=targeted

    A reboot is required for the changes to take effect.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281249'
  tag rid: 'SV-281249r1197242_rule'
  tag stig_id: 'RHEL-10-700400'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-85715r1197241_fix'
  tag cci: ['CCI-002696']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("sestatus | grep policy") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
