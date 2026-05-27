control 'SV-280973' do
  title 'RHEL 10 must have the "pcscd" service set to active.'
  desc <<~DESC
    The information system ensures that even if it is compromised, that compromise will not affect credentials stored on the authentication device.

    The daemon program for "pcsc-lite" and the MuscleCard framework is "pcscd". It is a resource manager that coordinates communications with smart card readers, smart cards, and cryptographic tokens that are connected to the system.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 has the "pcscd" socket set to active with the following command:

    $ systemctl is-active pcscd.socket
    active

    If the "pcscd" socket is not active, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "pcscd" socket set to active with the following command:

    $ sudo systemctl enable --now pcscd.socket
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280973'
  tag rid: 'SV-280973r1165274_rule'
  tag stig_id: 'RHEL-10-200611'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-85439r1165273_fix'
  tag cci: ['CCI-004046']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe service('pcscd.socket') do
    it { should be_enabled }
    it { should be_running }
  end
end
