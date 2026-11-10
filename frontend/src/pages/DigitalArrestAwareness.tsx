import { useState } from 'react';
import {
  AlertTriangle, ShieldAlert, Phone, ExternalLink, Video,
  CheckCircle2, XCircle, ArrowRight, RefreshCw, UserCheck, Scale, FileText
} from 'lucide-react';

interface ScenarioStep {
  id: number;
  situation: string;
  callerStatement: string;
  options: {
    text: string;
    isSafe: boolean;
    feedback: string;
  }[];
}

const interactiveScenarios: ScenarioStep[] = [
  {
    id: 1,
    situation: "You receive an incoming Skype / WhatsApp video call from a user named 'Cyber Crime HQ New Delhi'. A person wearing what looks like a police uniform with badges is sitting in front of a blue backdrop with official-looking logos.",
    callerStatement: "Mr./Ms. Citizen, a courier parcel dispatched under your Aadhaar number containing 150 grams of narcotics and 6 fraudulent passports was intercepted at Mumbai International Airport. A Non-Bailable Arrest Warrant has been sanctioned by the Chief Judicial Magistrate. You are now placed under DIGITAL ARREST. Keep your camera on and do not tell anyone.",
    options: [
      {
        text: "Apologize, stay on the video call, and ask them how much penalty you need to pay to clear your name.",
        isSafe: false,
        feedback: "DANGEROUS! This is precisely what scammers want. Staying on call isolates you psychologically, and paying a 'penalty' is an extortion transfer into a criminal mule account."
      },
      {
        text: "Disconnect the call immediately, block the number, and dial 1930 to report the incident to cyber authorities.",
        isSafe: true,
        feedback: "CORRECT & SAFE! Indian law enforcement never conducts interrogations, executes warrants, or places citizens under arrest via WhatsApp/Skype video calls. Disconnecting breaks their psychological hold."
      },
      {
        text: "Ask them to send the arrest warrant on WhatsApp first so you can verify the government stamp.",
        isSafe: false,
        feedback: "INCORRECT! Scammers possess convincingly forged PDF documents with fake Supreme Court seals, CBI logos, and fabricated signatures. Engaging further allows them to intimidate you with forged papers."
      }
    ]
  },
  {
    id: 2,
    situation: "The caller shows an 'Asset Verification Mandate' bearing a fake National Emblem and says all your bank accounts will be frozen within 30 minutes for money laundering.",
    callerStatement: "To prove your bank deposits are legitimate and not drug money, you must immediately liquidate your Fixed Deposits and transfer the total amount of ₹6,50,000 into the Reserve Bank of India Temporary Escrow Verification Account. Once audited, the funds will be returned in 15 minutes.",
    options: [
      {
        text: "Log into netbanking and execute the transfer to the 'RBI Verification Account' to avoid going to jail.",
        isSafe: false,
        feedback: "CRITICAL MISTAKE! The Reserve Bank of India NEVER maintains verification or escrow accounts for citizens. Any money transferred will be immediately laundered through layered mule accounts and cash ATMs."
      },
      {
        text: "Refuse to transfer any money. Inform the caller that you will visit your local police station in person, then hang up.",
        isSafe: true,
        feedback: "CORRECT! Law enforcement and courts NEVER require citizens to transfer money to 'prove legitimacy' of personal savings. Legitimate investigations never demand instant bank wire transfers."
      },
      {
        text: "Transfer a smaller token amount (like ₹10,000) to see if they are telling the truth.",
        isSafe: false,
        feedback: "DANGEROUS! Any transfer confirms your vulnerability and will cause scammers to escalate threats for the remaining balance."
      }
    ]
  },
  {
    id: 3,
    situation: "The scammer notices you hesitating and begins shouting aggressively with simulated police siren noises in the background.",
    callerStatement: "If you cut this call for even 5 seconds, our local SWAT team will break down your front door, confiscate all your electronics, and parade you before the media! Keep this confidential from your spouse or children!",
    options: [
      {
        text: "Beg them not to send police, lock your room door, and keep family members outside.",
        isSafe: false,
        feedback: "DANGEROUS! Isolation is the scammer's primary psychological weapon. Cutting off contact with loved ones prevents rational advice from breaking the spell."
      },
      {
        text: "Recognize the psychological pressure tactic. Disconnect immediately, talk to your family, and contact 1930 or visit the nearest police station.",
        isSafe: true,
        feedback: "CORRECT! Real law enforcement does not issue dramatic threats over video calls to prevent you speaking with your family or legal counsel."
      }
    ]
  }
];

export default function DigitalArrestAwareness() {
  const [currentScenario, setCurrentScenario] = useState(0);
  const [selectedOption, setSelectedOption] = useState<number | null>(null);

  const scenario = interactiveScenarios[currentScenario];

  const handleNext = () => {
    setSelectedOption(null);
    setCurrentScenario((prev) => (prev + 1) % interactiveScenarios.length);
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Absolute Legal Fact Notice */}
      <div className="bg-red-600 text-white rounded-2xl p-6 shadow-lg border-4 border-red-700">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-white text-red-600 rounded-xl flex-shrink-0">
            <Scale className="w-8 h-8" />
          </div>
          <div>
            <span className="text-xs font-black tracking-widest uppercase bg-red-800/80 px-2.5 py-0.5 rounded">
              CRITICAL LEGAL REALITY
            </span>
            <h1 className="text-2xl font-black mt-2 leading-tight">
              THERE IS NO LEGAL PROVISION FOR "DIGITAL ARREST" IN INDIA
            </h1>
            <p className="text-sm text-red-100 mt-2 font-medium leading-relaxed">
              Under the Code of Criminal Procedure (CrPC) and Bharatiya Nagarik Suraksha Sanhita (BNSS), no police department,
              CBI, ED, NIA, Narcotics Control Bureau, Customs, or Court has the legal authority to arrest, detain, or interrogating
              citizens over a WhatsApp, Skype, or video call.
            </p>
            <p className="text-xs text-red-200 mt-3 font-semibold uppercase tracking-wider">
              DO NOT TRANSFER MONEY TO ANYONE THREATENING YOU OVER A VIDEO CALL.
            </p>
          </div>
        </div>
      </div>

      {/* Emergency Helpline Bar */}
      <div className="card flex flex-col sm:flex-row items-center justify-between gap-4 bg-gray-900 text-white border-0 py-4">
        <div className="flex items-center gap-3">
          <Phone className="w-6 h-6 text-red-400" />
          <div>
            <div className="text-xs text-gray-400 font-semibold uppercase">National Cybercrime Helpline</div>
            <div className="text-lg font-black text-red-400">Dial 1930 (Toll-Free, 24x7)</div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <a
            href="https://cybercrime.gov.in"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-xs font-bold transition-all text-white"
          >
            <span>Report on cybercrime.gov.in</span>
            <ExternalLink className="w-4 h-4" />
          </a>
        </div>
      </div>

      {/* Interactive Scenario Simulator */}
      <div className="card border-2 border-blue-200">
        <div className="flex items-center justify-between border-b border-gray-200 pb-3">
          <div className="flex items-center gap-2">
            <Video className="w-5 h-5 text-blue-600" />
            <h2 className="text-base font-bold text-gray-900">
              Interactive Simulation: Video Call Extortion Scenario ({scenario.id} of {interactiveScenarios.length})
            </h2>
          </div>
          <button
            onClick={() => {
              setCurrentScenario(0);
              setSelectedOption(null);
            }}
            className="text-xs font-semibold text-gray-500 hover:text-blue-600 flex items-center gap-1"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Restart
          </button>
        </div>

        {/* Situation Description */}
        <div className="mt-4 p-4 bg-gray-50 border border-gray-200 rounded-lg text-sm text-gray-700 leading-relaxed">
          <span className="font-bold text-gray-900 block mb-1">Scenario Setting:</span>
          {scenario.situation}
        </div>

        {/* Fake Caller Dialogue Box */}
        <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
          <div className="flex items-center gap-2 text-xs font-bold text-red-800 uppercase tracking-wide">
            <AlertTriangle className="w-4 h-4" /> Impersonated Officer Dialogue:
          </div>
          <p className="mt-1.5 text-sm text-red-950 font-medium italic">
            "{scenario.callerStatement}"
          </p>
        </div>

        {/* Response Options */}
        <div className="mt-5 space-y-3">
          <p className="text-xs font-bold text-gray-700 uppercase tracking-wider">
            Choose Your Response:
          </p>

          {scenario.options.map((opt, idx) => (
            <button
              key={idx}
              onClick={() => setSelectedOption(idx)}
              className={`w-full text-left p-4 rounded-xl border text-sm transition-all ${
                selectedOption === idx
                  ? opt.isSafe
                    ? 'border-green-500 bg-green-50 ring-2 ring-green-500'
                    : 'border-red-500 bg-red-50 ring-2 ring-red-500'
                  : 'border-gray-300 hover:border-gray-400 bg-white'
              }`}
            >
              <div className="flex items-start gap-3">
                <span className="font-bold text-gray-500 text-xs mt-0.5">[{idx + 1}]</span>
                <span className="font-medium text-gray-900">{opt.text}</span>
              </div>

              {/* Feedback revelation */}
              {selectedOption === idx && (
                <div className={`mt-3 pt-3 border-t text-xs font-medium flex items-start gap-2 ${
                  opt.isSafe ? 'border-green-200 text-green-900' : 'border-red-200 text-red-900'
                }`}>
                  {opt.isSafe ? (
                    <CheckCircle2 className="w-4 h-4 text-green-600 flex-shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-4 h-4 text-red-600 flex-shrink-0 mt-0.5" />
                  )}
                  <span>{opt.feedback}</span>
                </div>
              )}
            </button>
          ))}
        </div>

        {/* Next step button */}
        {selectedOption !== null && (
          <div className="mt-5 flex justify-end">
            <button
              onClick={handleNext}
              className="btn-primary flex items-center gap-2"
            >
              <span>{currentScenario + 1 < interactiveScenarios.length ? 'Next Scenario Phase' : 'Cycle Scenarios'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>

      {/* Breakdown: Modus Operandi & Psychological Tactics */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="card">
          <h2 className="text-base font-bold text-gray-900 flex items-center gap-2">
            <FileText className="w-5 h-5 text-blue-600" />
            The Extortion Playbook
          </h2>
          <ul className="mt-3 space-y-2 text-xs text-gray-700 leading-relaxed">
            <li className="flex items-start gap-2">
              <span className="text-blue-600 font-bold">•</span>
              <span><strong>The Hook:</strong> Call from 'FedEx' or 'Customs' alleging an intercepted package with MDMA and passports in your name.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-600 font-bold">•</span>
              <span><strong>The Transfer:</strong> Seamless handoff to fake 'Police Officers' or 'CBI Officials' on video call.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-600 font-bold">•</span>
              <span><strong>The Studio Set:</strong> Scammers operate from mock setups with police barricades, state seals, and walkie-talkie audio tracks.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-600 font-bold">•</span>
              <span><strong>Forged Decrees:</strong> Displaying high-resolution fake Supreme Court arrest warrants and bank asset freezing orders.</span>
            </li>
          </ul>
        </div>

        <div className="card">
          <h2 className="text-base font-bold text-gray-900 flex items-center gap-2">
            <UserCheck className="w-5 h-5 text-purple-600" />
            Psychological Manipulation
          </h2>
          <ul className="mt-3 space-y-2 text-xs text-gray-700 leading-relaxed">
            <li className="flex items-start gap-2">
              <span className="text-purple-600 font-bold">•</span>
              <span><strong>Isolation Tactics:</strong> Forbidding the victim from hanging up, consulting lawyers, or alerting family members.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-purple-600 font-bold">•</span>
              <span><strong>Manufactured Panic:</strong> Giving artificial 30-minute deadlines before "paramilitary teams raid your home".</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-purple-600 font-bold">•</span>
              <span><strong>The Safe Escrow Myth:</strong> Conning victims into believing money transferred to their personal bank accounts is "safe government custody".</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-purple-600 font-bold">•</span>
              <span><strong>Sleep Deprivation:</strong> Keeping victims on call continuously for 24–48 hours to impair rational cognitive judgment.</span>
            </li>
          </ul>
        </div>
      </div>

      {/* Official Government Disclaimer */}
      <div className="bg-gray-100 border border-gray-300 rounded-xl p-4 text-xs text-gray-600 leading-relaxed">
        <strong>Transparency & Disclaimer:</strong> THREATNEX is an independent cybersecurity awareness and threat detection platform.
        It is NOT an official government agency. For reporting official cyber crime in India, citizens must use the official Ministry of Home Affairs portal at
        <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer" className="text-blue-700 underline font-semibold ml-1">
          https://cybercrime.gov.in
        </a> or call the national cyber crime helpline at <strong>1930</strong>.
      </div>
    </div>
  );
}
