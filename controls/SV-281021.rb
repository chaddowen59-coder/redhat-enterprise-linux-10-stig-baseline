control 'SV-281021' do
  title 'RHEL 10 must be configured so that the "/etc/gshadow" file is owned by "root".'
  desc <<~DESC
    The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the "/etc/gshadow" file is owned by "root" with the following command:

    $ sudo stat -c "%U %n" /etc/gshadow
    root /etc/gshadow

    If the "/etc/gshadow" file does not have an owner of "root", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the owner of the file "/etc/gshadow" is set to "root" by running the following command:

    $ sudo chown root /etc/gshadow
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281021'
  tag rid: 'SV-281021r1165418_rule'
  tag stig_id: 'RHEL-10-400020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85487r1165417_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("stat -c \"%U %n\" /etc/gshadow") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
