control 'SV-281068' do
  title 'RHEL 10 must enforce mode "0000" or less permissive for the "/etc/gshadow" file to prevent unauthorized access.'
  desc <<~DESC
    The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the "/etc/gshadow" file has mode "0000" with the following command:

    $ sudo stat -c "%a %n" /etc/gshadow
    0 /etc/gshadow

    If a value of "0" is not returned, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the mode of the "/etc/gshadow" file is set to "0000" by running the following command:

    $ sudo chmod 0000 /etc/gshadow
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281068'
  tag rid: 'SV-281068r1165559_rule'
  tag stig_id: 'RHEL-10-400255'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85534r1165558_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("stat -c \"%a %n\" /etc/gshadow") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
