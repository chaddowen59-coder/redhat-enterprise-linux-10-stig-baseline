control 'SV-281229' do
  title 'RHEL 10 must prevent code from being executed on file systems that are imported via Network File System (NFS).'
  desc <<~DESC
    The "noexec" mount option causes the system not to execute binary files. This option must be used for mounting any file system not containing approved binary as they may be incompatible. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If no NFS mounts are configured, this requirement is not applicable.

    Verify RHEL 10 has the "noexec" option configured for all NFS mounts with the following command:

    $ sudo grep nfs /etc/fstab
    192.168.22.2:/mnt/export /data nfs4 rw,nosuid,nodev,noexec,sync,soft,sec=krb5:krb5i:krb5p

    If the system is mounting file systems via NFS and the "noexec" option is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to prevent code from being executed on file systems that are imported via NFS.

    Update each NFS mounted file system to use the "noexec" option on file systems that are being imported via NFS.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281229'
  tag rid: 'SV-281229r1166639_rule'
  tag stig_id: 'RHEL-10-700105'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85695r1166638_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep nfs /etc/fstab") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
