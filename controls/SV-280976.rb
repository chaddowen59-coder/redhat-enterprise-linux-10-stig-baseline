control 'SV-280976' do
  title 'RHEL 10 must use the common access card (CAC) smart card driver.'
  desc <<~DESC
    Smart card login provides two-factor authentication stronger than that provided by a username and password combination. Smart cards leverage public key infrastructure to provide and verify credentials. Configuring the smart card driver helps to prevent the use of unauthorized smart cards.

    Satisfies: SRG-OS-000104-GPOS-00051, SRG-OS-000106-GPOS-00053, SRG-OS-000107-GPOS-00054, SRG-OS-000109-GPOS-00056, SRG-OS-000108-GPOS-00055
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 loads the CAC driver with the following command:

    $ sudo opensc-tool --get-conf-entry app:default:card_drivers
    cac

    If "cac" is not listed as a card driver, or no line is returned for "card_drivers", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to load the CAC driver:

    $ sudo opensc-tool --set-conf-entry app:default:card_drivers:cac

    Restart the pcscd service with the following command for the changes to take effect:

    $ sudo systemctl restart pcscd
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280976'
  tag rid: 'SV-280976r1165283_rule'
  tag stig_id: 'RHEL-10-200621'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-85442r1165282_fix'
  tag cci: ['CCI-000764', 'CCI-000766', 'CCI-000765', 'CCI-004045']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("opensc-tool --get-conf-entry app:default:card_drivers") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
