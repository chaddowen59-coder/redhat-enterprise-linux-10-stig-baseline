control 'SV-281227' do
  title 'RHEL 10 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a command line user login.'
  desc <<~DESC
    Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.

    Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000228-GPOS-00088
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 displays the Standard Mandatory DOD Notice and Consent Banner before granting access to the operating system via a command line login screen with the following command:

    $ cat /etc/issue

    If the banner is set correctly, it will return the following text:

    "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

    If the banner text does not match the Standard Mandatory DOD Notice and Consent Banner exactly, or the line is commented out, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via command line login.

    Edit the "/etc/issue" file to replace the default text with the Standard Mandatory DOD Notice and Consent Banner. The DOD-required text is:

    "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281227'
  tag rid: 'SV-281227r1184627_rule'
  tag stig_id: 'RHEL-10-700040'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-85693r1166632_fix'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("cat /etc/issue") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
