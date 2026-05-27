control 'SV-281022' do
  title 'RHEL 10 must be configured so that the "/etc/gshadow" file is group-owned by "root".'
  desc <<~DESC
    The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the "/etc/gshadow" file is group-owned by "root" with the following command:

    $ sudo stat -c "%G %n" /etc/gshadow
    root /etc/gshadow

    If the "/etc/gshadow" file does not have a group owner of "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the group of the "/etc/gshadow" file is set to "root" by running the following command:

    $ sudo chgrp root /etc/gshadow
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281022'
  tag rid: 'SV-281022r1165421_rule'
  tag stig_id: 'RHEL-10-400025'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85488r1165420_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("stat -c \"%G %n\" /etc/gshadow") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
