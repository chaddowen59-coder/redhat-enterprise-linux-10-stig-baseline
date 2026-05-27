control 'SV-281295' do
  title 'RHEL 10 must automatically exit interactive command shell user sessions after 15 minutes of inactivity.'
  desc <<~DESC
    Terminating an idle interactive command shell user session within a short time period reduces the window of opportunity for unauthorized personnel to take control of it when left unattended in a virtual terminal or physical console.

    Satisfies: SRG-OS-000163-GPOS-00072, SRG-OS-000029-GPOS-00010
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured to exit interactive command shell user sessions after 10 minutes of inactivity or less with the following command:

    $ sudo grep -i tmout /etc/profile /etc/profile.d/*.sh
    /etc/profile.d/tmout.sh:declare -xr TMOUT=600

    If "TMOUT" is not set to "600" or less in a script located in the "/etc/'profile.d/" directory, is missing, or is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to exit interactive command shell user sessions after 15 minutes of inactivity.

    Add or edit the following line in "/etc/profile.d/tmout.sh":

    #!/bin/bash

    declare -xr TMOUT=600
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281295'
  tag rid: 'SV-281295r1166837_rule'
  tag stig_id: 'RHEL-10-700920'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-85761r1166836_fix'
  tag cci: ['CCI-001133', 'CCI-000057']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -i tmout /etc/profile /etc/profile.d/*.sh") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
