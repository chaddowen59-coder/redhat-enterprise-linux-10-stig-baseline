control 'SV-281057' do
  title 'RHEL 10 must enforce root group ownership of the "/etc/audit/" directory.'
  desc <<~DESC
    The "/etc/audit/" directory contains files that ensure the proper auditing of command execution, privilege escalation, file manipulation, and more. Protection of this directory is critical for system security.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enforces root group ownership of the "/etc/audit/" directory with the following command:

    $ sudo stat -c "%G %n" /etc/audit/
    root /etc/audit/

    If "/etc/audit/" does not have a group owner of "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the "/etc/audit/" directory is group-owned by "root" with the following command:

    $ sudo chgrp root /etc/audit/
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281057'
  tag rid: 'SV-281057r1165526_rule'
  tag stig_id: 'RHEL-10-400200'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-85523r1165525_fix'
  tag cci: ['CCI-000171']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("stat -c \"%G %n\" /etc/audit/") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
