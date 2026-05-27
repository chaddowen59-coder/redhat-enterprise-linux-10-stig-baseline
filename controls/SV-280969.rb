control 'SV-280969' do
  title 'RHEL 10 must have the "fapolicy" module installed.'
  desc <<~DESC
    The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as allowlisting.

    Using an allowlist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities. Verification of allowlisted software occurs prior to execution or at system startup.

    User home directories/folders may contain information of a sensitive nature. Nonprivileged users should coordinate any sharing of information with a system administrator through shared resources.

    RHEL 10 ships with many optional packages. One such package is a file access policy daemon called "fapolicyd". This is a userspace daemon that determines access rights to files based on attributes of the process and file. It can be used to either blocklist or allowlist processes or file access.

    Proceed with caution with enforcing the use of this daemon. Improper configuration may render the system nonfunctional. The "fapolicyd" API is not namespace aware and can cause issues when launching or running containers.

    Satisfies: SRG-OS-000370-GPOS-00155, SRG-OS-000368-GPOS-00154
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 has the "fapolicyd" package installed with the following command:

    $ sudo dnf list --installed fapolicyd
    Installed Packages
    fapolicyd.x86_64                            1.3.3-102.el10                            @rhel-10-for-x86_64-appstream-rpms

    If the "fapolicyd" package is not installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "fapolicyd" package installed with the following command:

    $ sudo dnf -y install fapolicyd
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280969'
  tag rid: 'SV-280969r1195358_rule'
  tag stig_id: 'RHEL-10-200600'
  tag gtitle: 'SRG-OS-000370-GPOS-00155'
  tag fix_id: 'F-85435r1165261_fix'
  tag cci: ['CCI-001774', 'CCI-001764']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('fapolicyd') do
    it { should_not be_installed }
  end
end
