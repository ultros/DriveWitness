# DriveWitness privacy policy

Effective October 4, 2026. Publisher: **BioThreat Corporation, doing business as Novus Mercatura**. Novus Mercatura is a DBA of BioThreat Corporation. Creator: Jesse Lee Shelley.

This policy covers the official DriveWitness Windows application and CLI. It describes the current application, including copies distributed through GitHub or the Microsoft Store. It does not cover Microsoft's Store services, GitHub, LinkedIn, Cloudflare, or a third party's modified build.

## Information processed on your computer

DriveWitness reads files in the drives or folders you select to create and verify a filesystem baseline. It hashes file contents locally and records paths, names, sizes, timestamps, attributes, file/volume identifiers, cryptographic hashes, verification provenance, scan settings, errors, and scan history. Paths and error messages can contain personal information. It does not copy ordinary file contents into the evidence database.

Evidence also includes a machine identifier derived from the machine name, Windows MachineGuid, and processor identifier. Hardware/capability discovery inspects operating system, CPU, memory, storage, and volume information. Review annotations and verification events can record your Windows domain/user name, notes, review sets, and timestamps. Reports or manifests may contain this metadata.

The application stores preferences, window state, recent database paths, filters, and saved views under `%LOCALAPPDATA%\DriveWitness`. Scans are stored in the SQLite evidence database you choose. Review notes are stored separately in `<evidence>.review.db`. SQLite journals, temporary verification databases, and any logs or exports you request may contain related information. Signing passwords remain in application memory for the session. Signing and anonymization key files are selected and managed by you.

## Purpose, storage, and security

Processing supports the scans, integrity checks, comparisons, evidence review, and exports you request. Your databases, reports, and settings remain in your chosen local storage unless you place them in a synchronized/shared location or share them yourself. DriveWitness does not encrypt these files automatically. Windows permissions and your storage protections control access. Cryptographic hashes and signatures detect specified changes; they do not provide confidentiality or guarantee a trustworthy endpoint.

DriveWitness does not automatically send evidence, file contents, paths, hashes, notes, or usage analytics to Novus Mercatura, BioThreat Corporation, or the creator. It has no Publisher account system, advertising SDK, automatic crash reporting, or Publisher telemetry service. Publisher does not sell your scan data or use it for advertising. The application has no automatic Publisher retention period because Publisher does not receive the local evidence. You choose how long to retain it.

## Optional network activity and external services

The network clock observation option is **off by default**. If you enable it in Advanced settings or with `--network-time`, DriveWitness sends an HTTPS HEAD request to `https://www.cloudflare.com/` to read a Date header. Cloudflare and the network services handling the connection can receive your IP address and normal connection/request metadata. The request does not include your evidence, paths, hashes, or annotations. The result is an untrusted clock observation, not a trusted timestamp. Disable the option to avoid this application request. Cloudflare's own privacy terms govern its handling of that connection: https://www.cloudflare.com/privacypolicy/.

Opening project, creator, or support links launches your browser. Those sites receive normal browser/network information under their own privacy policies. Microsoft may process acquisition, account, payment, update, diagnostic, or usage information through Windows and the Store under its own settings and policy: https://privacy.microsoft.com/privacystatement. These services operate separately from DriveWitness; the current application does not request Store analytics or transmit local evidence to them.

Reading files in a cloud-synchronized folder can cause Windows or your cloud provider to retrieve file content. Choosing network drives, shared paths, or synchronized output folders can expose data to the services and users controlling those locations. DriveWitness does not control their storage, retention, or transmission.

## Your controls and access

Choose the drives/folders, include/exclude filters, database and export destinations, and optional network settings before scanning. You can cancel a scan; partial evidence is retained for inspection. Open, search, inspect, and export your databases through the GUI or CLI. Removing a scan from the catalog hides it; it does not erase its evidence.

Optional HMAC anonymization masks configured roots and names, but other metadata, sizes, hashes, notes, and exported information can still identify files or people. Inspect output before sharing it. Keep anonymization keys separate if you need to verify original files later.

To delete local data, close DriveWitness and remove the databases, review sidecars, associated SQLite journals, exports, logs, and settings you no longer need. Remove copies and backups from any shared or synchronized storage separately. Uninstalling the application is not a request to erase external evidence. Follow your own legal or organizational retention obligations.

## Contact and support information

Publisher: BioThreat Corporation, doing business as Novus Mercatura. For private privacy or licensing inquiries, contact Jesse Lee Shelley through https://linkedin.com/in/jesse-shelley. Public product support is available at https://github.com/ultros/DriveWitness/issues. Do not include personal information, evidence databases, credentials, or key files in public issues.

If you voluntarily provide information in a support conversation, it is used to respond to that request and retained only as reasonably needed for support and applicable legal obligations. The communication platform applies its own privacy and retention terms. You may request access, correction, or deletion of information you provided to Publisher through the private contact above, subject to applicable law. This does not delete evidence kept solely on your own computer.

This policy is available before scanning through the application's **Privacy** button and at https://github.com/ultros/DriveWitness/blob/main/PRIVACY.md. Material changes will be reflected in the dated policy shipped with a release and its public copy.
