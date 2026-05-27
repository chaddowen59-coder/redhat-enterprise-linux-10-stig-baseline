control 'SV-281214' do
  title 'RHEL 10 must ensure the password complexity module is enabled in the "password-auth" file.'
  desc <<~DESC
    Enabling Pluggable Authentication Module (PAM) password complexity permits enforcement of strong passwords and consequently makes the system less prone to dictionary attacks.

    Satisfies: SRG-OS-000069-GPOS-00037, SRG-OS-000070-GPOS-00038
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 uses "pwquality" to enforce the password complexity rules in the "password-auth" file with the following command:

    $ sudo grep pam_pwquality /etc/pam.d/password-auth
    password required pam_pwquality.so

    If the command does not return a line containing the value "pam_pwquality.so", or the line is commented out, this is a finding.

    If the system administrator can demonstrate that the required configuration is contained in a PAM configuration file included or substacked from the "system-auth" file, this is not a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to use "pwquality" to enforce password complexity rules.

    Add the following line to the "/etc/pam.d/password-auth" file (or modify the line to have the required value):

    password required pam_pwquality.so
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281214'
  tag rid: 'SV-281214r1166594_rule'
  tag stig_id: 'RHEL-10-600620'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-85680r1166593_fix'
  tag cci: ['CCI-004066']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep pam_pwquality /etc/pam.d/password-auth") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
