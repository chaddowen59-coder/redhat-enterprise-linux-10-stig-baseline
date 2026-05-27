control 'SV-281082' do
  title 'RHEL 10 must define default permissions for all authenticated users in such a way that the user can read and modify only their own files.'
  desc <<~DESC
    Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 defines default permissions for all authenticated users in such a way that the user can only read and modify their own files with the following command:

    Note: If the value of the "umask" parameter is set to "000" in "/etc/login.defs" file, the Severity is raised to a CAT I.

    $ sudo grep -i umask /etc/login.defs
    umask 077

    If the value for the "umask" parameter is not "077", or the "umask" parameter is missing or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to define default permissions for all authenticated users in such a way that the user can read and modify only their own files.

    Add or edit the lines for the "umask" parameter in the "/etc/login.defs" file to "077":

    umask 077
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281082'
  tag rid: 'SV-281082r1195406_rule'
  tag stig_id: 'RHEL-10-400325'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85548r1195405_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -i umask /etc/login.defs") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
