import { useState, useEffect } from 'react';
import {
  GraduationCap, Award, CheckCircle2, XCircle, ArrowRight,
  RotateCcw, Sparkles, Shield, ChevronRight
} from 'lucide-react';
import { getQuizQuestions, submitQuiz } from '../services/api';
import type { QuizQuestion } from '../types';
import toast from 'react-hot-toast';

export default function SecurityQuiz() {
  const [level, setLevel] = useState<'beginner' | 'intermediate' | 'advanced'>('beginner');
  const [questions, setQuestions] = useState<QuizQuestion[]>([]);
  const [currentIdx, setCurrentIdx] = useState(0);
  const [answers, setAnswers] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [finalResult, setFinalResult] = useState<any>(null);

  const startQuiz = async (selectedLevel: 'beginner' | 'intermediate' | 'advanced') => {
    setLoading(true);
    setFinalResult(null);
    setCurrentIdx(0);
    setAnswers({});
    setLevel(selectedLevel);

    try {
      const res = await getQuizQuestions(selectedLevel, 10);
      setQuestions(res.data);
    } catch (err) {
      toast.error('Failed to load quiz questions');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    startQuiz('beginner');
  }, []);

  const handleSelectOption = (qId: string, optionIdx: number) => {
    if (answers[qId] !== undefined) return; // Prevent changing answer once selected
    setAnswers((prev) => ({ ...prev, [qId]: optionIdx }));
  };

  const handleNext = () => {
    if (currentIdx + 1 < questions.length) {
      setCurrentIdx(currentIdx + 1);
    } else {
      handleSubmitQuiz();
    }
  };

  const handleSubmitQuiz = async () => {
    setSubmitting(true);
    const formattedAnswers = Object.entries(answers).map(([qid, ans]) => ({
      question_id: qid,
      selected_answer: ans
    }));

    try {
      const res = await submitQuiz(formattedAnswers, level);
      setFinalResult(res.data);
      toast.success('Quiz submitted successfully!');
    } catch (err) {
      toast.error('Failed to submit quiz results');
    } finally {
      setSubmitting(false);
    }
  };

  const currentQ = questions[currentIdx];
  const selectedAnswer = currentQ ? answers[currentQ.id] : undefined;

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      {/* Quiz Intro Header */}
      <div className="card border-l-4 border-l-blue-600">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-gray-900 flex items-center gap-2">
              <GraduationCap className="w-6 h-6 text-blue-600" />
              Cyber Readiness & Security Intelligence Quiz
            </h1>
            <p className="text-xs text-gray-600 mt-1">
              Evaluate your capability to identify phishing lures, fake websites, UPI fraud mechanics, and digital arrest coercion.
            </p>
          </div>

          {/* Difficulty Level Buttons */}
          <div className="flex items-center gap-1.5 bg-gray-100 p-1 rounded-xl self-start sm:self-auto">
            {(['beginner', 'intermediate', 'advanced'] as const).map((lvl) => (
              <button
                key={lvl}
                onClick={() => startQuiz(lvl)}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold capitalize transition-all ${
                  level === lvl
                    ? 'bg-blue-700 text-white shadow-sm'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>
        </div>
      </div>

      {loading ? (
        <div className="card text-center py-16 text-gray-500 text-sm">
          Preparing question challenges...
        </div>
      ) : finalResult ? (
        /* Results Summary Screen */
        <div className="card border-2 border-blue-200 text-center p-8 space-y-6">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-50 text-blue-700 mx-auto">
            <Award className="w-8 h-8" />
          </div>

          <div>
            <span className="text-xs font-bold text-gray-500 uppercase tracking-wider">
              {level.toUpperCase()} LEVEL ASSESSMENT COMPLETED
            </span>
            <h2 className="text-3xl font-extrabold text-gray-900 mt-1">
              Score: {finalResult.score} / {finalResult.total} ({finalResult.percentage}%)
            </h2>
            <p className="text-sm font-semibold mt-2">
              {finalResult.passed ? (
                <span className="text-green-700 inline-flex items-center gap-1 bg-green-50 px-3 py-1 rounded-full border border-green-200">
                  <CheckCircle2 className="w-4 h-4" /> Certification Readiness: Passed (Proficient)
                </span>
              ) : (
                <span className="text-amber-700 inline-flex items-center gap-1 bg-amber-50 px-3 py-1 rounded-full border border-amber-200">
                  <Shield className="w-4 h-4" /> Recommended: Review Cyber Awareness Guides and Retake
                </span>
              )}
            </p>
          </div>

          {/* Answer Review List */}
          <div className="text-left space-y-3 pt-6 border-t border-gray-200 max-h-96 overflow-y-auto">
            <h3 className="text-sm font-bold text-gray-900">Detailed Answer Review:</h3>
            {finalResult.results?.map((resItem: any, idx: number) => (
              <div
                key={idx}
                className={`p-4 rounded-xl border text-xs leading-relaxed ${
                  resItem.is_correct ? 'bg-green-50/50 border-green-200' : 'bg-red-50/50 border-red-200'
                }`}
              >
                <div className="flex items-start gap-2">
                  {resItem.is_correct ? (
                    <CheckCircle2 className="w-4 h-4 text-green-600 flex-shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-4 h-4 text-red-600 flex-shrink-0 mt-0.5" />
                  )}
                  <div className="flex-1">
                    <span className="font-bold text-gray-900">{resItem.question}</span>
                    <div className="mt-2 text-gray-700">
                      <strong>Your Answer:</strong> {resItem.options[resItem.selected_answer] || 'None'}
                    </div>
                    {!resItem.is_correct && (
                      <div className="mt-1 text-green-800">
                        <strong>Correct Answer:</strong> {resItem.options[resItem.correct_answer]}
                      </div>
                    )}
                    <div className="mt-2 p-2 bg-white/70 rounded border border-gray-200 text-gray-600 italic">
                      {resItem.explanation}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="pt-4 flex justify-center gap-3">
            <button
              onClick={() => startQuiz(level)}
              className="btn-primary flex items-center gap-2"
            >
              <RotateCcw className="w-4 h-4" /> Retake {level.toUpperCase()} Quiz
            </button>
          </div>
        </div>
      ) : currentQ ? (
        /* Active Question Display */
        <div className="card space-y-5">
          {/* Progress Header */}
          <div className="flex items-center justify-between text-xs text-gray-500 font-semibold border-b border-gray-100 pb-3">
            <span>Question {currentIdx + 1} of {questions.length}</span>
            <span className="px-2.5 py-0.5 rounded bg-blue-50 text-blue-700 uppercase">
              {currentQ.category || level}
            </span>
          </div>

          {/* Progress Bar */}
          <div className="w-full bg-gray-100 h-1.5 rounded-full overflow-hidden">
            <div
              className="bg-blue-600 h-full transition-all duration-300"
              style={{ width: `${((currentIdx + 1) / questions.length) * 100}%` }}
            />
          </div>

          {/* Question Text */}
          <h2 className="text-base font-bold text-gray-900 leading-snug">
            {currentQ.question}
          </h2>

          {/* Options */}
          <div className="space-y-2.5">
            {currentQ.options.map((opt, optIdx) => (
              <button
                key={optIdx}
                onClick={() => handleSelectOption(currentQ.id, optIdx)}
                className={`w-full text-left p-3.5 rounded-xl border text-sm transition-all flex items-start gap-3 ${
                  selectedAnswer === optIdx
                    ? 'border-blue-600 bg-blue-50 font-semibold text-blue-900 ring-1 ring-blue-600'
                    : 'border-gray-200 hover:border-gray-300 bg-white text-gray-800'
                }`}
              >
                <span className="flex items-center justify-center w-5 h-5 rounded-full bg-gray-100 text-gray-700 text-xs font-bold flex-shrink-0 mt-0.5">
                  {String.fromCharCode(65 + optIdx)}
                </span>
                <span>{opt}</span>
              </button>
            ))}
          </div>

          {/* Action Button */}
          <div className="pt-4 flex justify-end">
            <button
              onClick={handleNext}
              disabled={selectedAnswer === undefined || submitting}
              className="btn-primary flex items-center gap-2"
            >
              <span>{currentIdx + 1 < questions.length ? 'Next Question' : 'Submit Assessment'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      ) : (
        <div className="card text-center py-10 text-gray-500">
          No questions available for this level.
        </div>
      )}
    </div>
  );
}
