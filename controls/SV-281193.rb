control 'SV-281193' do
  title 'RHEL 10 must enforce password complexity rules for the "root" account.'
  desc <<~DESC
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that must be tested before the password is compromised.

    Satisfies: SRG-OS-000072-GPOS-00040, SRG-OS-000071-GPOS-00039, SRG-OS-000070-GPOS-00038, SRG-OS-000266-GPOS-00101, SRG-OS-000078-GPOS-00046, SRG-OS-000480-GPOS-00225, SRG-OS-000069-GPOS-00037
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 enforces password complexity rules for the "root" account.

    Check if "root" user is required to use complex passwords with the following command:

    $ sudo grep enforce_for_root /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
    /etc/security/pwquality.conf:enforce_for_root

    If "enforce_for_root" is commented out or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to enforce password complexity on the "root" account.

    Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "enforce_for_root" parameter:

    enforce_for_root
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281193'
  tag rid: 'SV-281193r1166531_rule'
  tag stig_id: 'RHEL-10-600405'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-85659r1166530_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep enforce_for_root /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
