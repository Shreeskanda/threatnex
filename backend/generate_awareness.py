import json
import os

categories = [
    {
        "id": "digital-arrest-scam",
        "title": "Digital Arrest Scam",
        "slug": "digital-arrest-scam",
        "icon": "ShieldAlert",
        "severity_level": "critical",
        "description": "Criminals impersonate police, CBI, ED, customs or RBI officials on video calls, falsely claiming your Aadhaar or phone is tied to narcotics, money laundering, or illegal parcels, placing you under a fake 'Digital Arrest'.",
        "how_it_works": "The victim receives an intimidating phone call claiming a parcel sent in their name containing drugs, fake passports or SIM cards was intercepted at customs or courier hubs. The caller transfers the victim to 'officers' on Skype or WhatsApp video who wear simulated police uniforms in fake studio backdrops. The victim is told they are under 'digital arrest', cannot hang up or contact family, and must transfer all savings to a 'Supreme Court / RBI verification account' for asset clearance.",
        "warning_signs": [
            "Video call from caller claiming to be Police, CBI, ED or Narcotics Bureau",
            "Demands to stay on continuous video call or keep camera on indefinitely",
            "Threats of imminent physical arrest if you disconnect or notify relatives",
            "Demands to transfer money into 'escrow accounts' or 'RBI verification accounts' for clearance",
            "Forged documents with fake National Emblem, CBI or Court stamps sent via WhatsApp",
            "Urgent coercion to liquidate fixed deposits or transfer entire bank balances"
        ],
        "example_scenario": "Ramesh receives a call from someone claiming to be FedEx Customs stating a parcel addressed to him containing 5 passports and MDMA was seized in Mumbai. In panic, he is transferred to a Skype call where an individual in a police uniform warns that a non-bailable warrant is issued against his Aadhaar. To prove his bank funds are legitimate, he is forced to transfer ₹8,50,000 to a 'court verification account'. Once transferred, the scammers disappear.",
        "manipulation_tactics": "Fear induction, authority intimidation, psychological isolation (forbidding communication with family or lawyers), fake judicial documents, simulated police sirens and radio chatter in the background.",
        "how_to_identify": "Remember: The Indian legal code (CrPC / BNSS) does NOT recognise any concept of 'Digital Arrest'. Genuine police or central agencies NEVER interrogate or arrest citizens over WhatsApp/Skype video calls, nor do they ever request money transfers to verify legitimacy.",
        "prevention_tips": [
            "Never attend video calls from unknown numbers alleging legal charges",
            "Remember that genuine law enforcement issues formal physical summons, never Skype/WhatsApp arrests",
            "Disconnect immediately and dial the National Cyber Helpline 1930",
            "Never transfer funds to any bank account under threat or coercion",
            "Verify any courier notification directly with the courier's official customer support"
        ],
        "victim_steps": [
            "Call 1930 immediately to freeze fraudulent bank beneficiary accounts within the golden hour",
            "File a formal complaint on the National Cyber Crime Reporting Portal at https://cybercrime.gov.in",
            "Take screenshots of call logs, chat transcripts, forged documents and bank transaction references",
            "Visit your local police station / Cyber Crime Cell to lodge an FIR"
        ]
    },
    {
        "id": "phishing",
        "title": "Phishing",
        "slug": "phishing",
        "icon": "MailWarning",
        "severity_level": "critical",
        "description": "Deceptive emails or fraudulent portals designed to masquerade as reputable organisations to steal sensitive login credentials, banking details, or identity documents.",
        "how_it_works": "Attackers send emails mimicking banks, utility providers, tech platforms or tax portals. The email contains urgent warnings regarding account suspension or password expiry, prompting the victim to click a link leading to a lookalike website.",
        "warning_signs": [
            "Mismatched sender domain (e.g. support@sbi-online-service.net instead of sbi.co.in)",
            "Urgent deadlines threatening account closure within 24 hours",
            "Generic greetings such as 'Dear Customer' rather than your registered name",
            "Embedded links leading to misspelled domain names or IP addresses"
        ],
        "example_scenario": "A victim receives an email purportedly from their banking portal stating: 'Your netbanking KYC has lapsed. Click here to verify within 12 hours or your account will be frozen.' The link redirects to a clone site that captures their customer ID and password.",
        "manipulation_tactics": "Manufactured urgency, fear of financial loss, impersonation of respected institutions.",
        "how_to_identify": "Examine the sender's full email address and hover over hyperlinks to inspect the destination domain before clicking.",
        "prevention_tips": [
            "Always type official URLs directly into your browser bookmark bar",
            "Enable Two-Factor Authentication (2FA) with hardware keys or authenticator apps",
            "Never enter credentials on websites displaying SSL/TLS warnings",
            "Use email security filters and endpoint protection"
        ],
        "victim_steps": [
            "Change affected passwords immediately from a clean device",
            "Revoke active web sessions and enable multi-factor authentication",
            "Notify your bank to freeze cards or netbanking access if credentials were leaked",
            "Report the phishing URL to cybercrime.gov.in and Google Safe Browsing"
        ]
    },
    {
        "id": "smishing",
        "title": "Smishing (SMS Phishing)",
        "slug": "smishing",
        "icon": "MessageSquareWarning",
        "severity_level": "high",
        "description": "Phishing attacks conducted via SMS text messages containing malicious links, fake delivery updates, or fraudulent banking alerts.",
        "how_it_works": "Victims receive SMS messages claiming unpaid electricity bills, failed courier delivery, pending bank rewards, or PAN card deactivation with a shortened link.",
        "warning_signs": [
            "SMS sent from random 10-digit mobile numbers instead of registered headers like VK-HDFCBK",
            "Shortened URLs (bit.ly, tinyurl) masking the true destination",
            "Threat of immediate electricity disconnection tonight at 9:30 PM",
            "Requests to install an APK file from a link"
        ],
        "example_scenario": "'Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous bill was not updated. Please immediately call 9876543210 or click bit.ly/power-pay.'",
        "manipulation_tactics": "Urgency, threats of immediate utility disconnection, curiosity over undelivered packages.",
        "how_to_identify": "Notice irregular sender numbers; genuine utility alerts originate from government or company alpha-numeric sender IDs.",
        "prevention_tips": [
            "Never tap links received via SMS from unknown senders",
            "Verify utility payments only through the electricity board's official application or website",
            "Never download Android APK files from links in SMS messages"
        ],
        "victim_steps": [
            "Block and report the sender number using TRAI's DND app or 1909",
            "If an APK was installed, disconnect phone from Wi-Fi/data and perform a factory reset",
            "Contact your bank if any financial details were submitted"
        ]
    },
    {
        "id": "vishing",
        "title": "Vishing (Voice Phishing)",
        "slug": "vishing",
        "icon": "PhoneCall",
        "severity_level": "high",
        "description": "Phone call scams where fraudsters pose as bank officers, insurance agents, or tech support to extract PINs, passwords, or OTPs.",
        "how_it_works": "The fraudster calls the victim claiming their credit card points are expiring or suspicious transactions were observed. They sound professional and ask the victim to read out an OTP sent to their mobile 'to cancel the fraud transaction'.",
        "warning_signs": [
            "Caller asking for OTP, CVV, or ATM PIN under any pretext",
            "Background office noises or caller insisting they are from the bank's fraud department",
            "Caller becomes aggressive or irritable when questioned"
        ],
        "example_scenario": "A caller claims to be from the fraud detection team of your bank: 'Someone attempted a ₹45,000 transaction on your debit card from Bangalore. To block this transaction immediately, please read the 6-digit cancellation code sent to your phone.'",
        "manipulation_tactics": "Authority impersonation, panic creation, helpful facade.",
        "how_to_identify": "Banks repeatedly clarify that employees NEVER ask for OTPs, PINs, or CVV numbers over phone calls.",
        "prevention_tips": [
            "Hang up immediately if anyone asks for an OTP",
            "Call your bank's official helpline number printed on the back of your debit card",
            "Never disclose personal or financial information over the phone"
        ],
        "victim_steps": [
            "Immediately block the compromised card via your mobile banking app",
            "Call 1930 to report fraudulent debits",
            "Lodge an incident report on cybercrime.gov.in"
        ]
    },
    {
        "id": "upi-fraud",
        "title": "UPI Fraud",
        "slug": "upi-fraud",
        "icon": "CreditCard",
        "severity_level": "critical",
        "description": "Deceptive schemes exploiting UPI payment mechanics, such as misleading users into entering their UPI PIN under the belief they are receiving money.",
        "how_it_works": "Scammers pose as buyers on OLX or Facebook Marketplace, claiming they want to purchase an item. They send a UPI 'Collect Request' or QR code and tell the seller: 'To receive the payment, enter your UPI PIN.'",
        "warning_signs": [
            "Entering your UPI PIN to 'receive' money — PIN is ONLY required to SEND money",
            "Buyer agreeing to purchase without negotiating or seeing the physical item",
            "Requests to scan a QR code to claim rewards or lottery amounts"
        ],
        "example_scenario": "You post an old sofa on OLX for ₹8,000. A buyer offers to pay immediately via Google Pay, sends a payment request of ₹8,000 and tells you: 'Please enter your UPI PIN to approve the credit to your account.' Once you enter your PIN, ₹8,000 is debited from your account.",
        "manipulation_tactics": "Eagerness to pay quickly, confusion over UPI technical workflow, fake payment confirmation screenshots.",
        "how_to_identify": "Golden Rule of UPI: You NEVER need to enter your UPI PIN to receive money. PIN is strictly for debiting your account.",
        "prevention_tips": [
            "Never enter your UPI PIN unless you intend to transfer funds out",
            "Reject unsolicited 'Collect' requests in payment apps",
            "Verify UPI ID (VPA) and recipient name displayed before completing transfers"
        ],
        "victim_steps": [
            "Dial 1930 immediately to register the transaction with the Indian Cyber Crime Coordination Centre (I4C)",
            "Block UPI access temporarily via your bank's netbanking portal",
            "File a dispute in your UPI application (BHIM, PhonePe, GPay)"
        ]
    },
    {
        "id": "qr-code-scams",
        "title": "QR Code Scams (Quishing)",
        "slug": "qr-code-scams",
        "icon": "QrCode",
        "severity_level": "high",
        "description": "Tampered physical QR stickers in merchant stores or digital QR codes designed to direct users to phishing sites or trigger unauthorized money deductions.",
        "how_it_works": "Fraudsters paste their own printed QR code stickers over genuine merchant payment codes at stores, or send QR codes via WhatsApp claiming scanning it will deposit cashback.",
        "warning_signs": [
            "Physical QR stickers appearing overlaid, peelable, or placed on top of official merchant boards",
            "Prompts requiring payment authorisation when expecting to receive funds",
            "QR codes directing to shortened URLs or unknown domains"
        ],
        "example_scenario": "A victim visits a local petrol pump or cafe where a malicious sticker was pasted over the merchant's QR code. The victim scans and pays ₹1,500 without verifying the beneficiary name displayed on screen.",
        "manipulation_tactics": "Exploiting habitual behaviour, visual camouflage.",
        "how_to_identify": "Always check the verified merchant business name shown in your payment app before entering your PIN.",
        "prevention_tips": [
            "Confirm the payee name with the shopkeeper before completing transactions",
            "Inspect physical QR plates for suspicious peeling or stickers layered over them",
            "Avoid scanning QR codes from random emails or social media contests"
        ],
        "victim_steps": [
            "Notify the merchant so other customers are protected",
            "Report the rogue VPA to the payment service provider",
            "File a complaint at 1930"
        ]
    },
    {
        "id": "otp-fraud",
        "title": "OTP Fraud",
        "slug": "otp-fraud",
        "icon": "KeyRound",
        "severity_level": "critical",
        "description": "Social engineering techniques employed to trick victims into sharing One-Time Passwords used for financial transactions or account takeovers.",
        "how_it_works": "The attacker triggers a password reset or purchase transaction on the victim's account, then contacts the victim using various pretexts (courier delivery verification, lottery reward, telecom network upgrade) to obtain the OTP.",
        "warning_signs": [
            "Unsolicited OTP received on phone while on call with a stranger",
            "SMS containing OTP explicitly stating: 'Do not share this OTP with anyone, including bank staff'",
            "Caller insisting the OTP is a 'cancellation code' or 'reference number'"
        ],
        "example_scenario": "A caller claiming to be an Airtel executive says your 4G SIM is being upgraded to 5G. They state: 'I have sent an SMS with a confirmation code to activate 5G tower signals. Please read out the 6-digit code.' The code is actually a password reset OTP for WhatsApp or netbanking.",
        "manipulation_tactics": "Tech jargon, pretending the code is harmless, claiming urgency.",
        "how_to_identify": "Read the full text of the OTP SMS carefully. It always states the exact transaction amount and purpose.",
        "prevention_tips": [
            "Treat OTPs like your ATM PIN — never read, forward, or disclose them to anyone",
            "Carefully review the purpose specified in the OTP message before entering it anywhere",
            "Never type an OTP on any website reached via a chat or SMS link"
        ],
        "victim_steps": [
            "Call your bank helpline immediately to lock netbanking and cards",
            "Change passwords on email and financial accounts",
            "Report to 1930 immediately"
        ]
    },
    {
        "id": "sim-swap-fraud",
        "title": "SIM Swap Fraud",
        "slug": "sim-swap-fraud",
        "icon": "Smartphone",
        "severity_level": "critical",
        "description": "Scammers obtain a duplicate SIM card of your mobile number from the telecom operator using forged identity documents, intercepting all your SMS OTPs.",
        "how_it_works": "After gathering the victim's personal details through phishing, the scammer approaches a telecom store claiming the victim's SIM was lost and provides forged ID. Once the duplicate SIM activates, the victim's phone loses network connectivity completely while the scammer receives all 2FA OTPs.",
        "warning_signs": [
            "Sudden and prolonged loss of cellular network signal in areas with normally strong reception",
            "SMS notifications from telecom provider acknowledging a SIM change or upgrade request you didn't initiate",
            "Inability to make calls or receive texts despite active balance"
        ],
        "example_scenario": "Anurag notices his phone shows 'No Service' on Monday morning. He assumes it is temporary network maintenance. Meanwhile, fraudsters with the duplicate SIM reset his netbanking password and siphon ₹12 lakhs using SMS OTPs.",
        "manipulation_tactics": "Identity theft, exploiting telecom verification loopholes, targeting victims during holidays or weekends.",
        "how_to_identify": "If your phone abruptly loses all cellular reception for more than 30 minutes, investigate immediately with your telecom provider.",
        "prevention_tips": [
            "Contact your carrier immediately if your mobile loses signal unexpectedly",
            "Set a SIM PIN / carrier security PIN if offered by your operator",
            "Transition financial 2FA from SMS to authenticator apps where supported",
            "Do not post your primary phone number publicly on social networks"
        ],
        "victim_steps": [
            "Call your telecom customer service immediately from another phone to block the duplicate SIM",
            "Contact your banks immediately to place an operational hold on all accounts",
            "Lodge an urgent complaint on 1930 and cybercrime.gov.in"
        ]
    },
    {
        "id": "fake-job-offers",
        "title": "Fake Job Offers & Task Scams",
        "slug": "fake-job-offers",
        "icon": "Briefcase",
        "severity_level": "high",
        "description": "Bogus employment offers or daily part-time tasks (like rating videos or liking Google Maps locations) that lure victims into depositing money into investment traps.",
        "how_it_works": "Victims receive Telegram or WhatsApp messages offering ₹2,000–₹5,000 per day for simple work-from-home tasks like liking YouTube videos. Initially, victims receive small payouts of ₹300 to build trust. Then they are invited to 'prepaid merchant tasks' where they must deposit increasing sums of money to unlock larger returns.",
        "warning_signs": [
            "Job offers sent via unsolicited WhatsApp or Telegram messages",
            "Unrealistically high remuneration for trivial tasks (e.g. ₹500 for liking a video)",
            "Requirement to pay 'registration fees', 'training kit charges', or 'security deposits'",
            "Demands to join Telegram groups where fake participants post fake earnings screenshots"
        ],
        "example_scenario": "Pooja receives a message: 'Work from home! Earn ₹3,000 daily reviewing hotels.' She likes 3 links and receives ₹600 via UPI. Encouraged, she joins a Telegram task group where the administrator convinces her to do a 'premium trading task' depositing ₹50,000. When she tries to withdraw her ₹90,000 balance, she is told she must deposit ₹1,00,000 more in tax clearance fees.",
        "manipulation_tactics": "Sunk cost fallacy, social proof via coordinated fake group members, initial micro-payouts to establish credibility.",
        "how_to_identify": "Legitimate employers never conduct hiring exclusively over Telegram, nor do they ever charge candidates money to work.",
        "prevention_tips": [
            "Never pay money to secure a job or part-time work",
            "Block unsolicited Telegram/WhatsApp recruitment recruiters",
            "Verify vacancies on the organisation's verified careers page"
        ],
        "victim_steps": [
            "Stop all further deposits immediately, regardless of what the administrators claim",
            "Save chat transcripts, beneficiary UPI IDs, and bank transfer receipts",
            "Report immediately to 1930 and cybercrime.gov.in"
        ]
    },
    {
        "id": "investment-and-trading-scams",
        "title": "Investment and Trading Scams",
        "slug": "investment-and-trading-scams",
        "icon": "TrendingUp",
        "severity_level": "critical",
        "description": "Fraudulent stock trading apps and bogus high-yield investment schemes promising guaranteed daily returns or insider IPO allocations.",
        "how_it_works": "Victims are recruited via social media advertisements into VIP WhatsApp/Telegram trading groups run by individuals impersonating prominent SEBI-registered brokers. Victims are directed to install a third-party APK app showing simulated massive profits. When they try to withdraw, their funds are frozen.",
        "warning_signs": [
            "Promises of guaranteed 20%–50% monthly returns with zero market risk",
            "Requirement to deposit funds into individual savings accounts rather than registered broker accounts",
            "App not available on Google Play / Apple App Store, installed via web link or APK",
            "Requirement to pay 'capital gains tax' or 'withdrawal fees' upfront before withdrawing profits"
        ],
        "example_scenario": "Sunil joins a WhatsApp group named 'Institutional Institutional Equity Club'. The admin claims exclusive access to pre-IPO quotas. Sunil downloads their proprietary app and deposits ₹5,00,000 into various merchant accounts. The app displays his balance as ₹22,00,000. However, when he requests a withdrawal, he is asked for an additional 20% GST deposit.",
        "manipulation_tactics": "Greed exploitation, fake community cheerleading, manipulated dashboard numbers showing artificial profits.",
        "how_to_identify": "Check whether the broker is officially registered on SEBI's portal (sebi.gov.in). SEBI brokers never accept deposits into individual personal bank accounts.",
        "prevention_tips": [
            "Trade only through SEBI-registered brokers and official apps",
            "Treat any promise of guaranteed high returns as an immediate red flag",
            "Never transfer investment funds into personal savings accounts"
        ],
        "victim_steps": [
            "Report the fraud immediately on 1930 and file an FIR",
            "Notify SEBI's SCORES grievance portal",
            "Collect all transaction records, chat logs, and bank statements"
        ]
    },
    {
        "id": "cryptocurrency-scams",
        "title": "Cryptocurrency Scams",
        "slug": "cryptocurrency-scams",
        "icon": "Coins",
        "severity_level": "high",
        "description": "Deceptive cryptocurrency investment schemes, rug pulls, fake exchange platforms, and cloud mining scams stealing digital assets.",
        "how_it_works": "Attackers promote fake cryptocurrency trading platforms or arbitrage bots. Once users transfer Bitcoin or USDT to the platform's deposit address, the funds are swept into mixer wallets and the platform locks the user account.",
        "warning_signs": [
            "Unsolicited investment advice from romantic interests or acquaintances met online (Pig Butchering)",
            "Guaranteed daily returns in crypto (e.g. 5% daily compounding)",
            "Non-custodial wallet requests to connect to suspicious DApps or sign malicious smart contract permits"
        ],
        "example_scenario": "A victim meets someone on a dating app who gradually introduces them to a 'decentralized liquidity mining pool' guaranteeing 12% weekly return in USDT. The victim connects their wallet and approves an unlimited allowance transaction, allowing the malicious contract to drain $15,000 worth of crypto.",
        "manipulation_tactics": "Romance grooming, technical obscurity of blockchain transactions, irreversible nature of crypto transfers.",
        "how_to_identify": "Check platform registration, inspect smart contract approvals with tools like Revoke.cash, and avoid off-market crypto deals.",
        "prevention_tips": [
            "Use only compliant exchanges registered with the Financial Intelligence Unit (FIU-IND)",
            "Never share your 12/24-word wallet seed phrase with anyone",
            "Inspect token approval allowances before signing transactions in Web3 wallets"
        ],
        "victim_steps": [
            "Revoke all smart contract approvals using Revoke.cash or Etherscan",
            "Track transaction hashes on blockchain explorers",
            "File a complaint with cybercrime.gov.in and the local cyber cell"
        ]
    },
    {
        "id": "romance-scams",
        "title": "Romance Scams (Honey Trapping / Catfishing)",
        "slug": "romance-scams",
        "icon": "HeartOff",
        "severity_level": "high",
        "description": "Scammers create fictitious attractive online profiles to develop emotional bonds, eventually concocting emergency scenarios to extract substantial sums.",
        "how_it_works": "The scammer matches on dating apps or matrimonial platforms, posing as a foreign doctor, maritime engineer, or diplomat. Over months of communication, they gain deep trust. They announce they are sending an expensive gift box or travelling to visit, then claim to be detained at Delhi Airport customs requiring clearance duty fees.",
        "warning_signs": [
            "The person professes intense love very quickly but repeatedly finds excuses to avoid in-person meetings or live video calls",
            "Claims to be working overseas in high-profile international careers (UN doctor, oil rig engineer)",
            "Emergencies requiring urgent money: customs clearance fees, medical surgery, lost passport",
            "Requests to transfer money into third-party personal bank accounts"
        ],
        "example_scenario": "Deepa interacts with 'Dr. Michael' on a matrimonial portal. After 3 months of daily chatting, he says he shipped a diamond necklace and watch as an engagement present. Soon, Deepa receives a call from 'Customs Officer Sharma at IGI Airport' demanding ₹75,000 customs duty to release the package, threatening legal prosecution if she fails to pay.",
        "manipulation_tactics": "Emotional intimacy, romantic fantasy, guilt-tripping, fake authority involvement.",
        "how_to_identify": "Run reverse image searches on profile pictures; note refusal to conduct impromptu video calls.",
        "prevention_tips": [
            "Never send money or financial gifts to someone you have never met face-to-face",
            "Be skeptical of matches whose profiles seem overly polished or affluent",
            "Remember that Indian customs never calls recipients demanding personal bank transfers for duties"
        ],
        "victim_steps": [
            "Cease all communication and avoid sending any follow-up payments",
            "Preserve all chat logs, photographs, and bank receipts",
            "Lodge a report on cybercrime.gov.in and dial 1930"
        ]
    },
    {
        "id": "online-shopping-scams",
        "title": "Online Shopping Scams",
        "slug": "online-shopping-scams",
        "icon": "ShoppingBag",
        "severity_level": "medium",
        "description": "Bogus e-commerce storefronts and fraudulent social media sellers advertising luxury items at unbelievable discounts that take prepaid orders but never deliver.",
        "how_it_works": "Fraudsters create sleek websites or Instagram stores offering high-end electronics, designer clothing, or sneakers at 80% below retail value. After customers complete online prepayment, the seller blocks them or delivers cheap counterfeits.",
        "warning_signs": [
            "Prices drastically lower than market rate (e.g. iPhone 15 Pro for ₹15,000)",
            "No option for Cash on Delivery (COD); strictly prepaid via UPI",
            "Store contact details lack a registered physical address or landline phone",
            "Website domain registered only days or weeks ago"
        ],
        "example_scenario": "Karan sees an Instagram ad for branded sneakers at ₹999 (original ₹8,000). He orders through the link and pays via UPI. Days pass with no tracking update. The Instagram page changes handle and blocks his account.",
        "manipulation_tactics": "Lure of bargain discounts, limited-stock countdown timers, fake positive customer reviews.",
        "how_to_identify": "Look up domain age on WHOIS tools, check independent consumer grievance forums, and look for missing company registration numbers.",
        "prevention_tips": [
            "Stick to established, reputable e-commerce platforms",
            "Prefer Cash on Delivery for unfamiliar online shops",
            "Verify customer feedback on third-party review platforms"
        ],
        "victim_steps": [
            "Dispute the charge with your credit card issuer or UPI bank",
            "Report the fraudulent seller page to Instagram/Meta",
            "Lodge an e-commerce fraud complaint on the National Consumer Helpline (1915)"
        ]
    },
    {
        "id": "loan-app-scams",
        "title": "Predatory Loan App Scams",
        "slug": "loan-app-scams",
        "icon": "Banknote",
        "severity_level": "critical",
        "description": "Unregistered instant loan apps offering easy micro-loans that harvest device contacts and gallery photos to extort victims with morphed photographs.",
        "how_it_works": "Victims install instant loan apps from unofficial links. The app requests extensive permissions (contacts, storage, camera). A small loan of ₹5,000 is disbursed, with ₹2,000 deducted in fees. Within 5 days, recovery agents demand ₹10,000. When delayed, agents send morphed obscene pictures to the victim's entire contact list.",
        "warning_signs": [
            "App requesting full access to your phone contacts, gallery, and location before loan approval",
            "Absence of RBI NBFC registration credentials or Sanction Letter",
            "Extremely short repayment tenures (5–7 days) with exorbitant 100%+ processing charges",
            "Threats, abusive language, and blackmail from recovery callers"
        ],
        "example_scenario": "In urgent need of cash, Priya installs 'QuickCash' via an APK link. She receives ₹3,500. On day 6, recovery agents begin calling her parents and colleagues, threatening to circulate morphed compromising photos if ₹15,000 isn't paid within 2 hours.",
        "manipulation_tactics": "Social humiliation, blackmail with morphed media, harassment of friends and family.",
        "how_to_identify": "Verify the lending entity on the RBI's official list of registered Non-Banking Financial Companies (NBFCs). Legitimate loan apps never harass contacts.",
        "prevention_tips": [
            "Borrow only from RBI-regulated banks and verified NBFC apps on Google Play",
            "Never grant contact or media gallery permissions to lending apps",
            "Avoid downloading APK files for financial transactions"
        ],
        "victim_steps": [
            "Do not yield to blackmail extortion payments; paying invites further demands",
            "Inform family and close contacts that your phone data was compromised by an extortion racket",
            "File an urgent police complaint at your local cyber cell and on 1930"
        ]
    },
    {
        "id": "identity-theft",
        "title": "Identity Theft",
        "slug": "identity-theft",
        "icon": "Fingerprint",
        "severity_level": "high",
        "description": "Unauthorised acquisition and exploitation of your personal identifiers (Aadhaar, PAN, voter ID, passport) to take fraudulent loans, open mule bank accounts, or register SIM cards.",
        "how_it_works": "Criminals obtain photocopies or leaked scans of your Aadhaar card and PAN card from data breaches or unsecured document drops, then open dummy accounts to wash scam proceeds.",
        "warning_signs": [
            "Unexplained inquiries or unfamiliar loan accounts appearing on your CIBIL credit report",
            "Calls from collection agencies regarding credit cards you never opened",
            "Rejection of legitimate loan applications due to ruined credit scores"
        ],
        "example_scenario": "Mohan checks his annual credit score and discovers two active personal loans of ₹2,00,000 each in his name from fintech apps in Gurgaon. Criminals had applied using his compromised Aadhaar and PAN documents with a rented mobile number.",
        "manipulation_tactics": "Exploiting automated KYC systems, forged address proofs.",
        "how_to_identify": "Regularly audit your credit bureau report (CIBIL, Experian) and monitor registered SIMs using the Department of Telecommunications' TAFCOP portal.",
        "prevention_tips": [
            "Use Masked Aadhaar (where only last 4 digits are visible) for routine identification",
            "Lock your Aadhaar biometrics via the mAadhaar app or UIDAI portal",
            "Audit registered numbers in your name at https://tafcop.sancharsaathi.gov.in",
            "Shred physical copies of identity proofs before disposing"
        ],
        "victim_steps": [
            "Place a fraud alert on credit bureaus (CIBIL, CRIF, Experian)",
            "Lodge an identity theft FIR at the nearest police station",
            "Send formal written contestations to all financial institutions that issued fraudulent loans"
        ]
    },
    {
        "id": "social-media-account-hacking",
        "title": "Social Media Account Takeover",
        "slug": "social-media-account-hacking",
        "icon": "UserX",
        "severity_level": "medium",
        "description": "Hijacking of Instagram, WhatsApp, or Facebook accounts via credential stuffing, phishing, or session hijacking to scam your friends for emergency funds.",
        "how_it_works": "Once an account is seized, the attacker messages the victim's close contacts: 'I am in a medical emergency at the hospital. Can you please GPay ₹15,000 urgently? I will return it tomorrow morning.'",
        "warning_signs": [
            "Security alerts notifying login from unknown device or country",
            "Friends informing you that they received bizarre urgent financial requests from your handle",
            "Inability to log into your account with your known password"
        ],
        "example_scenario": "Neha's Instagram is taken over through a fake 'Copyright Infringement' phishing link. Within an hour, her account messages 50 followers asking for ₹5,000 urgent medical aid via UPI. Three friends transfer the amount before discovering the hack.",
        "manipulation_tactics": "Exploiting interpersonal trust and urgency among close friends and family.",
        "how_to_identify": "Sudden emergency requests from friends asking for money via UPI should always be verified with an offline phone call.",
        "prevention_tips": [
            "Enable app-based Two-Factor Authentication on all social media accounts",
            "Never click on 'Copyright Violation' or 'Blue Tick Verification' links sent via direct message",
            "Use strong, unique passphrases for every service"
        ],
        "victim_steps": [
            "Use the platform's account recovery portal immediately (e.g. instagram.com/hacked)",
            "Alert your friends on other channels not to transfer money to anyone messaging from your compromised account",
            "Report the incident on cybercrime.gov.in"
        ]
    },
    {
        "id": "remote-access-app-scams",
        "title": "Remote Access App Scams",
        "slug": "remote-access-app-scams",
        "icon": "MonitorX",
        "severity_level": "critical",
        "description": "Fraudsters induce victims to install remote desktop tools (AnyDesk, TeamViewer, RustDesk) allowing them to view your screen and take over mobile banking sessions.",
        "how_it_works": "Posing as bank tech support, telecom engineers, or customer service, the caller instructs the victim to download a 'support app' like AnyDesk. Once installed, the scammer asks the victim to read out the 9-digit code, granting full view and remote control of the device while the victim logs into netbanking.",
        "warning_signs": [
            "Caller asking you to download AnyDesk, TeamViewer, QuickSupport, or RustDesk to solve an issue",
            "Caller requesting the 9-digit connection code generated by the remote application",
            "Screen warning prompts indicating remote sharing is active"
        ],
        "example_scenario": "Vijay complains on Twitter about a failed refund. A fake customer care account replies with a phone number. When Vijay calls, the agent tells him to install 'AnyDesk Support' so they can approve his refund. While on call, the agent observes Vijay typing his banking password and triggers unauthorized transfers.",
        "manipulation_tactics": "Frustration exploitation, confusing technical terms, remote observation of credentials.",
        "how_to_identify": "No genuine financial institution or delivery company ever asks customers to install remote access applications.",
        "prevention_tips": [
            "Never install screen sharing or remote management apps at the behest of an incoming caller",
            "Never disclose connection codes shown inside AnyDesk or TeamViewer",
            "If someone insists on screen sharing, disconnect the call immediately"
        ],
        "victim_steps": [
            "Immediately turn on Airplane Mode or turn off Wi-Fi/mobile data to sever remote connection",
            "Uninstall the remote access application immediately",
            "Call your bank to freeze internet banking and card operations",
            "Report immediately to 1930"
        ]
    },
    {
        "id": "fake-customer-care-scams",
        "title": "Fake Customer Care Scams",
        "slug": "fake-customer-care-scams",
        "icon": "Headphones",
        "severity_level": "high",
        "description": "Criminals manipulate Google search results, Google Maps listings, and social media to display fraudulent support numbers for banks, airlines, or delivery services.",
        "how_it_works": "When a user searches for customer care numbers for Swiggy, Air India, or SBI on search engines, the top result or map location displays a fraudster's mobile number. When dialed, the scammer claims to facilitate the refund via UPI or a remote access app.",
        "warning_signs": [
            "Customer care number is a normal 10-digit mobile number rather than an official toll-free 1800 number",
            "Agent asking you to pay a ₹1 or ₹5 'verification fee' via UPI to process a refund",
            "Agent asking for remote desktop software installation"
        ],
        "example_scenario": "Geeta searches Google for 'Courier customer care number' to track a delayed parcel. She calls the number listed on a Google search result snippet. The person asks her to pay a ₹5 redelivery charge by clicking a UPI link. The link is actually a collect request for ₹50,000.",
        "manipulation_tactics": "Exploiting user distress, hijacking online business listings.",
        "how_to_identify": "Find official helpline numbers exclusively inside the verified mobile app or on the company's authentic website URL.",
        "prevention_tips": [
            "Never rely on unverified phone numbers from Google Search results or Maps",
            "Use only the in-app support chat found within the official corporate application",
            "Be aware that refunds are credited back automatically; you never need to pay a fee to receive a refund"
        ],
        "victim_steps": [
            "Notify your bank immediately if you authorized any transaction or shared details",
            "Dial 1930 without delay",
            "Suggest an edit on Google Maps to remove the fraudulent contact listing"
        ]
    },
    {
        "id": "tech-support-scams",
        "title": "Tech Support Scams",
        "slug": "tech-support-scams",
        "icon": "Laptop",
        "severity_level": "medium",
        "description": "Loud, flashing browser pop-ups displaying fake virus warnings and blaring audio alarms that instruct users to call a toll-free number for immediate 'Microsoft / Apple support'.",
        "how_it_works": "A malicious web page locks the browser in full-screen mode, displaying terrifying warnings like 'CRITICAL ALERT: Trojan Spyware Detected. Your computer has been locked.' The victim calls the number, connects to a scam call center, and is charged $200–$500 for fake cleanup software.",
        "warning_signs": [
            "Browser suddenly locks with full-screen popups and synthesized robotic audio alarms",
            "Prompt stating your PC is infected and instructing you to call a toll-free number immediately",
            "Demands for remote access to your computer to inspect Windows Event Viewer"
        ],
        "example_scenario": "An elderly user browsing recipe blogs encounters a popup with the Windows logo: 'Your computer is locked due to illegal activity. Call Microsoft Support at 1800-XXX-XXXX immediately.' The fake technician shows normal system event logs as 'dangerous viruses' and bills ₹25,000 for a bogus 5-year security license.",
        "manipulation_tactics": "Auditory panic, full-screen browser freeze, showing benign system logs as proof of hacking.",
        "how_to_identify": "Legitimate operating systems (Microsoft, Apple) NEVER display phone numbers in pop-ups or request you call them for virus removal.",
        "prevention_tips": [
            "Press Alt + F4 or open Task Manager (Ctrl + Shift + Esc) to close the locked browser window",
            "Install a reliable ad-blocker and browser security extension",
            "Never call phone numbers shown in alarming browser warnings"
        ],
        "victim_steps": [
            "Uninstall any software installed during the remote support call",
            "Run a full system scan with reputable antivirus software",
            "Dispute credit card charges with your bank"
        ]
    },
    {
        "id": "malware-and-ransomware",
        "title": "Malware and Ransomware",
        "slug": "malware-and-ransomware",
        "icon": "Bug",
        "severity_level": "critical",
        "description": "Malicious software programs that infiltrate computers or mobile devices to steal passwords, log keystrokes, or encrypt documents demanding extortion ransoms.",
        "how_it_works": "Users inadvertently download infected files from pirated software portals, torrents, or malicious email attachments (.zip, .iso, .exe, or macro-enabled documents). Ransomware silently encrypts all documents and photos, leaving a text note demanding ransom in cryptocurrency.",
        "warning_signs": [
            "Files suddenly change extension to unfamiliar strings (.locked, .crypt) and cannot be opened",
            "Desktop wallpaper replaced with extortion instructions",
            "Device running extremely slow with high CPU/disk activity when idle",
            "Antivirus software disabled or unable to launch"
        ],
        "example_scenario": "An accountant downloads a 'free cracked version' of office software from an untrusted forum. Within 20 minutes, all client financial spreadsheets are encrypted, and a README note appears demanding 0.5 Bitcoin within 72 hours to unlock files.",
        "manipulation_tactics": "Extortion deadlines, threats of permanent data destruction, leaked data publication.",
        "how_to_identify": "Sudden widespread inaccessible files with appended unknown extensions.",
        "prevention_tips": [
            "Maintain regular offline backups following the 3-2-1 backup rule",
            "Never download cracked software, keygens, or unauthorized APKs",
            "Keep operating system and applications updated with latest security patches"
        ],
        "victim_steps": [
            "Disconnect the affected computer from the local network and internet immediately",
            "Do not pay the ransom; payment does not guarantee file recovery and funds criminal syndicates",
            "Check NoMoreRansom.org to see if a free decryption tool exists for the specific ransomware variant",
            "Report to cybercrime.gov.in"
        ]
    },
    {
        "id": "fake-government-websites",
        "title": "Fake Government Portals",
        "slug": "fake-government-websites",
        "icon": "Building2",
        "severity_level": "critical",
        "description": "Counterfeit web portals mimicking official ministries, e-challan systems, PM schemes, or passport portals to collect fraudulent fees and identity documents.",
        "how_it_works": "Fraudsters create identical copies of government portals using domains like 'echallan-parivahan-gov.in' or 'pm-kisan-yojana.com'. Victims receive SMS messages about a traffic fine and pay on the fake portal, transmitting both their money and card details to the criminal group.",
        "warning_signs": [
            "Domain name ends in .com, .org, .in, or .net instead of the official .gov.in or .nic.in",
            "Spelling errors in the URL (e.g. incometaxindia-gov.org)",
            "Gateway insists on direct UPI transfers to personal or merchant VPAs",
            "Government crest or emblem appears distorted or low-resolution"
        ],
        "example_scenario": "Siddharth receives an SMS: 'Your vehicle has an unpaid traffic violation of ₹1,000. Pay within 24 hours at parivahan-challan-pay.in to avoid court summons.' He visits the site, which looks identical to the official Parivahan page, and pays the fine through a fake payment gateway.",
        "manipulation_tactics": "Legal fear, fear of court summons or passport suspension, official aesthetic mimicry.",
        "how_to_identify": "All authentic Central and State Government portals in India strictly end with .gov.in or .nic.in domains.",
        "prevention_tips": [
            "Always inspect the domain extension: authentic Indian government sites strictly use .gov.in or .nic.in",
            "Never trust government payment links received via SMS from random numbers",
            "Search for the service directly on official portals like india.gov.in"
        ],
        "victim_steps": [
            "Contact your bank to block the card used on the fraudulent portal",
            "Report the spoofed government domain to cybercrime.gov.in and CERT-In (incident@cert-in.org.in)",
            "Verify actual vehicle challan status on the genuine portal: echallan.parivahan.gov.in"
        ]
    },
    {
        "id": "lottery-and-prize-scams",
        "title": "Lottery and Prize Scams (KBC / Lucky Draw)",
        "slug": "lottery-and-prize-scams",
        "icon": "Trophy",
        "severity_level": "medium",
        "description": "Bogus lottery winnings, Kaun Banega Crorepati (KBC) lucky draws, or promotional giveaways claiming you won millions and must pay processing fees to claim.",
        "how_it_works": "The victim receives an image on WhatsApp featuring pictures of famous television hosts or Prime Ministers announcing a ₹25,00,000 lottery win. The caller explains that to disburse the prize, the winner must first deposit income tax / processing charges into specified bank accounts.",
        "warning_signs": [
            "Winning a lottery or contest you never purchased a ticket for or entered",
            "Requirement to pay upfront fees, taxes, or clearance charges to receive prize money",
            "Audio recordings in WhatsApp messages featuring simulated fanfare and excitement",
            "Demands to keep the prize secret until final disbursement"
        ],
        "example_scenario": "A message with a KBC lottery letterhead arrives on WhatsApp: 'Congratulations! Your SIM number won the 2024 KBC Lucky Draw of ₹25 Lakhs. Contact WhatsApp Manager Rana Pratap.' When contacted, 'Rana' asks for ₹12,500 government registration fee to transfer the cash.",
        "manipulation_tactics": "Excitement, windfall greed, artificial secrecy, impersonation of celebrity figures.",
        "how_to_identify": "You cannot win a lottery that you never entered. Legitimate lotteries deduct applicable taxes at source (TDS); they never ask winners to transfer money upfront.",
        "prevention_tips": [
            "Delete and report unsolicited WhatsApp lottery announcements",
            "Remember that legitimate contests never ask winners to pay fees to claim prizes",
            "Block and report the sender number immediately"
        ],
        "victim_steps": [
            "Stop sending any additional 'processing' payments",
            "Dial 1930 to report the beneficiary bank accounts",
            "File a complaint on cybercrime.gov.in"
        ]
    },
    {
        "id": "sextortion-and-blackmail-scams",
        "title": "Sextortion and Blackmail Scams",
        "slug": "sextortion-and-blackmail-scams",
        "icon": "VideoOff",
        "severity_level": "critical",
        "description": "Extortion schemes where criminals record or morph sexually explicit video footage of victims during video calls and threaten to distribute it to contacts unless paid.",
        "how_it_works": "The victim receives a video call on WhatsApp from an attractive stranger who begins undressing. The scammer screen-records the call showing the victim's face alongside explicit content, or uses AI to morph the victim's face onto nude imagery. Threatening calls from fake 'Delhi Police Cyber Cell officers' follow shortly demanding money to 'delete the viral video from YouTube.'",
        "warning_signs": [
            "Unexpected video call from unknown number with immediate explicit nudity",
            "Call from someone claiming to be an IPS officer or YouTube executive threatening to release a video",
            "Immediate demands for money transfer to settle the matter 'out of court'"
        ],
        "example_scenario": "Raghav answers an unknown WhatsApp video call. A woman appears and starts undressing. Raghav hangs up in shock within 5 seconds. Ten minutes later, he receives an edited video showing his face next to explicit clips, followed by a call from 'Inspector Vikram of Delhi Police' threatening to register an obscenity case unless ₹30,000 is sent to hush up the matter.",
        "manipulation_tactics": "Acute panic, shame, social humiliation, rapid dual-impersonation (blackmailer + fake police officer).",
        "how_to_identify": "Police never contact individuals over WhatsApp demanding money to delete viral videos. This is an extortion playbook operated by organised cyber gangs.",
        "prevention_tips": [
            "Never answer video calls from unknown phone numbers",
            "Adjust WhatsApp privacy settings to allow calls and profile photo access only to saved contacts",
            "Keep social media friend lists private"
        ],
        "victim_steps": [
            "Do NOT pay any money — payment guarantees continuous, escalating extortion demands",
            "Do not delete chat messages, call records, or transaction requests; they serve as digital evidence",
            "Confide in a trusted family member or counselor immediately",
            "Report immediately to 1930 and file a complaint on cybercrime.gov.in (National Cyber Crime Reporting Portal has a dedicated section for cyber crimes against women/children and sextortion)"
        ]
    },
    {
        "id": "business-email-compromise",
        "title": "Business Email Compromise (BEC)",
        "slug": "business-email-compromise",
        "icon": "Briefcase",
        "severity_level": "critical",
        "description": "Targeted corporate attacks where attackers compromise or spoof executive and vendor email accounts to redirect vendor invoices and multimillion-dollar wire payments.",
        "how_it_works": "Attackers compromise an executive's corporate mailbox or register a look-alike domain (e.g. acme-corp.com vs acrne-corp.com). They monitor email threads regarding pending vendor invoices. Just before payment execution, they send an email from the spoofed address: 'Please note our beneficiary bank details have changed due to an annual audit; remit payment to this new account.'",
        "warning_signs": [
            "Last-minute changes to vendor payment instructions or bank account details received by email",
            "Executive requesting urgent wire transfer with strict instructions to bypass standard verification protocols",
            "Slight variations in email domain letters (typosquatting)"
        ],
        "example_scenario": "A finance manager receives an email from the CEO's genuine address (compromised via phishing): 'I am boarding an overseas flight. Please expedite the ₹40,00,000 vendor payment to our new overseas account before 5 PM today. Treat as confidential.' The finance manager executes the transfer without voice verification.",
        "manipulation_tactics": "Executive authority, secrecy demands, time pressure, exploiting routine administrative processes.",
        "how_to_identify": "Any request altering supplier bank coordinates must trigger out-of-band verbal confirmation.",
        "prevention_tips": [
            "Mandate multi-person approval and secondary verbal phone verification for any bank detail changes",
            "Enforce strict SPF, DKIM, and DMARC policies on corporate email domains",
            "Deploy multi-factor authentication across all enterprise mailboxes"
        ],
        "victim_steps": [
            "Immediately contact the sending bank and request a SWIFT / wire recall or fund freeze",
            "Notify the beneficiary bank's fraud department",
            "Isolate compromised email accounts and perform forensic analysis",
            "Report to national cybersecurity authorities and file a formal cybercrime complaint"
        ]
    }
]

out_dir = r"C:\Users\Shreeskanda\.gemini\antigravity\scratch\cyber-sentinel\backend\app\data"
os.makedirs(out_dir, exist_ok=True)
out_path = os.path.join(out_dir, "awareness_content.json")

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(categories, f, indent=2, ensure_ascii=False)

print(f"Successfully wrote {len(categories)} categories to {out_path}")
