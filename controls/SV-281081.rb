control 'SV-281081' do
  title 'RHEL 10 must define default permissions for the c shell.'
  desc <<~DESC
    The "umask" controls the default access mode assigned to newly created files. A "umask" of "077" limits new files to mode "600" or less permissive. Although "umask" can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be "0". 

    This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify the RHEL 10 "umask" setting is configured correctly in the "/etc/csh.cshrc" file with the following command:

    Note: If the value of the "umask" parameter is set to "000" in the "/etc/csh.cshrc" file, the Severity is raised to a CAT I.

    $ sudo grep umask /etc/csh.cshrc
    umask 077

    If the value for the "umask" parameter is not "077", or the "umask" parameter is missing or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to define default permissions for all authenticated users using the c shell.

    Add or edit the lines for the "umask" parameter in the "/etc/csh.cshrc" file to "077":

    umask 077
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281081'
  tag rid: 'SV-281081r1184682_rule'
  tag stig_id: 'RHEL-10-400320'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85547r1165597_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep umask /etc/csh.cshrc") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
