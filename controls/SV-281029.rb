control 'SV-281029' do
  title 'RHEL 10 must be configured so that the "/etc/shadow" file is owned by "root".'
  desc <<~DESC
    The "/etc/shadow" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to "root" provides the designated owner with access to sensitive information, which could weaken the system security posture.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the "/etc/shadow" file is owned by "root" with the following command:

    $ sudo stat -c "%U %n" /etc/shadow
    root /etc/shadow

    If the "/etc/shadow" file does not have an owner of "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the owner of the "/etc/shadow" file is set to "root" by running the following command:

    $ sudo chown root /etc/shadow
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281029'
  tag rid: 'SV-281029r1165442_rule'
  tag stig_id: 'RHEL-10-400060'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85495r1165441_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("stat -c \"%U %n\" /etc/shadow") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
