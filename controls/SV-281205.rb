control 'SV-281205' do
  title 'RHEL 10 must restrict the use of the "su" command.'
  desc <<~DESC
    The "su" program allows commands to be run with a substitute user and group ID. It is commonly used to run commands as the root user. Limiting access to such commands is considered a good security practice.

    Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000312-GPOS-00123
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 requires users to be members of the "wheel" group to run "su".

    Verify the configuration with the following command:

    $ sudo grep pam_wheel /etc/pam.d/su
    auth             required        pam_wheel.so use_uid

    If a line for "pam_wheel.so" does not exist or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to require users to be in the "wheel" group to run the "su" command.

    Edit the configuration file:

    $ sudo vi /etc/pam.d/su

    Add the following lines:

    auth    required    pam_wheel.so use_uid
    $ sed '/^[[:space:]]*#[[:space:]]*auth[[:space:]]\+required[[:space:]]\+pam_wheel\.so[[:space:]]\+use_uid$/s/^[[:space:]]*#//' -i /etc/pam.d/su

    If necessary, create a "wheel" group and add administrative users to the group.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281205'
  tag rid: 'SV-281205r1166567_rule'
  tag stig_id: 'RHEL-10-600500'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-85671r1166566_fix'
  tag cci: ['CCI-002038', 'CCI-002165']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep pam_wheel /etc/pam.d/su") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
