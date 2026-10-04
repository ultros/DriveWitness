# Microsoft Store legal and publisher setup

Prepared October 4, 2026 for DriveWitness 3.1.2. This release prepares legal materials and publisher branding. The GitHub ZIP is not a Microsoft Store package or a certified Store submission.

## Publisher identity

| Field | Value |
| --- | --- |
| Legal publisher/company | BioThreat Corporation |
| Business/display name | Novus Mercatura |
| Relationship | Novus Mercatura is a DBA of BioThreat Corporation |
| Public attribution | Published by Novus Mercatura, a DBA of BioThreat Corporation |
| Creator and existing copyright owner | Jesse Lee Shelley |
| Product | DriveWitness |

Use the verified BioThreat Corporation company identity in Partner Center. Configure Novus Mercatura as the publisher display name only as allowed by that verified account. Use the exact package identity and Publisher value assigned by Partner Center when building an MSIX; a DBA string is not an MSIX identity. This repository does not invent a Partner Center Publisher ID or claim a copyright assignment from Jesse Lee Shelley to the corporation.

## Listing links and license terms

| Listing material | Public URL |
| --- | --- |
| Privacy policy | https://github.com/ultros/DriveWitness/blob/main/PRIVACY.md |
| Custom application license / additional license terms | https://github.com/ultros/DriveWitness/blob/main/STORE_EULA.txt |
| Incorporated free-use license | https://github.com/ultros/DriveWitness/blob/main/LICENSE |
| Third-party notices | https://github.com/ultros/DriveWitness/blob/main/THIRD_PARTY_NOTICES.md |
| Product support | https://github.com/ultros/DriveWitness/issues |
| Private licensing/privacy contact | https://linkedin.com/in/jesse-shelley |

Provide the custom EULA and incorporated LICENSE in the Store submission's license/product description materials before acquisition. Set the privacy URL and support URL in the listing. All terms are also shipped with the download; License, Store Terms, Privacy, and third-party texts are readable inside the GUI without a network connection. If a direct text URL is needed, use `https://raw.githubusercontent.com/ultros/DriveWitness/main/STORE_EULA.txt`.

The base license follows AllianceWatch's free-use/no-resale model. Version 2.1 expressly authorizes BioThreat Corporation DBA Novus Mercatura and its official Microsoft Store channel to distribute paid copies, while preserving existing free-use and earlier valid grants. Store customers receive no additional device/user/time restriction from Publisher. The EULA preserves the applicable Microsoft Usage Rules and mandatory consumer rights. A price for the official Store distribution does not revoke the free-use grant; disclose that relationship accurately if choosing a paid listing.

The application uses MIT, Apache-2.0, BSD-2-Clause and public-domain/CC0 dependencies. Their notices and full license texts remain in `licenses/` and the packaged application. No Microsoft Windows, Store SDK, or developer agreement text is relicensed as DriveWitness code. Accepting the applicable Microsoft developer agreement in Partner Center remains the publisher's responsibility.

## Submission details still required

1. Verify the company account, DBA/display name, contact address, any required private support email/telephone, and merchant/tax/payout details in Partner Center. No unverified address, email, phone, or registration number is published here.
2. Reserve the app identity and choose the supported packaging route. The current ZIP/PowerShell installer is a GitHub distribution. For an MSIX submission, build with the reserved identity, declare the desktop app capabilities, and validate the package. For an EXE/MSI submission, create a standalone silent installer, sign it and its PE files as required, and host immutable versioned binaries. The ZIP is not a substitute for either route.
3. Complete installation/uninstallation, Windows App Certification Kit and Store certification checks on the actual submission artifact. Existing code/GUI acceptance results do not establish Store certification. Review protection of personal evidence under policy 10.5.4 and any applicable consent requirements; current local databases are not automatically encrypted. Disclose that behavior and validate the storage protection used by the submitted product.
4. Set accurate Windows 11/x64 system requirements, supported locales, age rating, screenshots, category, pricing and certification notes. Explain local filesystem access and optional administrator/USN behavior. Do not advertise optional GPU acceleration, PDF export, trusted timestamping, or whole-drive speed guarantees that are not shipped.
5. Confirm whether Store analytics/error reports will be enabled. The current privacy policy describes an application with no Publisher telemetry and no requested Store analytics; update the policy and operating practices before adding publisher analytics or a new service.

## Microsoft sources

Checked October 4, 2026. The [App Developer Agreement](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/store/documents/legal/ada/fy26/MS.Store.ADAv8.10.EN.US.pdf), sections 4(h) and 4(i), covers privacy disclosures and supplying custom customer terms. Custom terms must preserve the applicable [Microsoft Usage Rules](https://support.microsoft.com/en-us/windows/apps/usage-rules-for-digital-goods-rules). The [Microsoft Services Agreement](https://www.microsoft.com/en-us/servicesagreement) describes the default application terms when different terms are not supplied.

[Store Policies 7.19](https://learn.microsoft.com/en-us/windows/apps/publish/store-policy-archive/store-policy-7-19) are effective on the preparation date. [Policies 7.20](https://learn.microsoft.com/en-us/windows/apps/publish/store-policies-and-code-of-conduct) were published September 15, 2026 and state an October 22, 2026 effective date. Recheck the policies, developer agreement, and market-specific disclosures on the actual submission date.

## Release verification

The Windows x64 binaries were built from source commit `fc3c191a1ff676d36e406b9fafb68220e58a7d6e`. Their company metadata is `BioThreat Corporation DBA Novus Mercatura`, and the GUI, CLI, exports and notices preserve Jesse Lee Shelley's creator credit. The source build had zero warnings/errors, and all 120 tests passed, including publisher attribution in all four report formats.

Packaged GUI acceptance passed offline legal document availability and tab selection, review draft retention, database switching/invalid input, live resource controls, full-digest clipboard copying, saved state, the minimum viewport, and simulated 100/125/150/200% control scaling. Startup to shown was 211 ms; the maximum scan heartbeat gap was 118 ms. These are local acceptance measurements, not Store certification or a whole-volume performance guarantee. Scanner/hash/query algorithms and schema version 2 are preserved. The previous [large-database audit](BUG_PERFORMANCE_AUDIT.md) retains its measurements and limitations.

Visual inspection found and fixed collapsed paragraph breaks when a Windows text box loaded LF-only documents. Legal and report dialogs now normalize line endings. The publisher credit and Privacy button fit the minimum viewport. Raw acceptance results and screenshots are in [docs/store/gui.json](docs/store/gui.json), [publisher](docs/store/legal-publisher.png), [Store terms](docs/store/legal-store-terms.png), [privacy](docs/store/legal-privacy.png), [third-party texts](docs/store/legal-third-party.png), and [minimum layout](docs/store/layout-minimum.png). Test results are retained in [docs/store/core.trx](docs/store/core.trx).
