control 'SV-281215' do
  title 'RHEL 10 must ensure the password complexity module is enabled in the "system-auth" file.'
  desc <<~DESC
    Enabling Pluggable Authentication Module (PAM) password complexity permits enforcement of strong passwords and consequently makes the system less prone to dictionary attacks.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 uses "pwquality" to enforce the password complexity rules in the "system-auth" file with the following command:

    $ sudo grep pam_pwquality /etc/pam.d/system-auth
    password required pam_pwquality.so

    If the command does not return a line containing the value "pam_pwquality.so", or the line is commented out, this is a finding.

    If the system administrator can demonstrate that the required configuration is contained in a PAM configuration file included or substacked from the "system-auth" file, this is not a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to use "pwquality" to enforce password complexity rules.

    Add the following line to the "/etc/pam.d/system-auth" file (or modify the line to have the required value):

    password required pam_pwquality.so
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281215'
  tag rid: 'SV-281215r1166597_rule'
  tag stig_id: 'RHEL-10-600630'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-85681r1166596_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep pam_pwquality /etc/pam.d/system-auth") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
