import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'

const TestResults = () => {
  const { testId } = useParams()
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [downloadingReport, setDownloadingReport] = useState(false)

  useEffect(() => {
    if (testId) {
      fetchResults()
    }
  }, [testId])

  const fetchResults = async () => {
    try {
      const response = await fetch(`http://localhost:5000/api/test/results/${testId}`)
      const data = await response.json()
      
      if (data.error) {
        setError(data.error)
      } else {
        setResults(data)
      }
    } catch (err) {
      setError('Failed to fetch test results')
    } finally {
      setLoading(false)
    }
  }

  const downloadReport = async (format = 'html') => {
    setDownloadingReport(true)
    try {
      const response = await fetch(`http://localhost:5000/api/test/report/${testId}?format=${format}`)
      const data = await response.json()
      
      if (data.error) {
        setError(data.error)
      } else if (data.download_url) {
        // Open download URL in new tab
        window.open(`http://localhost:5000${data.download_url}`, '_blank')
      }
    } catch (err) {
      setError('Failed to generate report')
    } finally {
      setDownloadingReport(false)
    }
  }

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-600'
    if (score >= 60) return 'text-yellow-600'
    return 'text-red-600'
  }

  const getScoreBg = (score) => {
    if (score >= 80) return 'bg-green-100'
    if (score >= 60) return 'bg-yellow-100'
    return 'bg-red-100'
  }

  const getRiskLevelColor = (level) => {
    switch (level?.toLowerCase()) {
      case 'low': return 'text-green-600 bg-green-100'
      case 'medium': return 'text-yellow-600 bg-yellow-100'
      case 'high': return 'text-red-600 bg-red-100'
      case 'critical': return 'text-red-800 bg-red-200'
      default: return 'text-gray-600 bg-gray-100'
    }
  }

  if (loading) {
    return (
      <div className="max-w-6xl mx-auto p-6">
        <div className="text-center py-12">
          <div className="w-16 h-16 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Running Tests...</h2>
          <p className="text-gray-600">This may take several minutes depending on the selected tests.</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="max-w-6xl mx-auto p-6">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <h2 className="text-xl font-semibold text-red-800 mb-2">Error</h2>
          <p className="text-red-600 mb-4">{error}</p>
          <Link
            to="/test"
            className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            Start New Test
          </Link>
        </div>
      </div>
    )
  }

  if (!results) {
    return (
      <div className="max-w-6xl mx-auto p-6">
        <div className="text-center py-12">
          <h2 className="text-xl font-semibold text-gray-900 mb-2">No Results Found</h2>
          <p className="text-gray-600 mb-4">The test results could not be found.</p>
          <Link
            to="/test"
            className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            Start New Test
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-8">
      {/* Header */}
      <div className="text-center">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Test Results</h1>
        <p className="text-gray-600">Comprehensive analysis for {results.url}</p>
        <p className="text-sm text-gray-500">Test ID: {results.test_id} | {new Date(results.timestamp).toLocaleString()}</p>
      </div>

      {/* Overall Score */}
      <div className="bg-white rounded-lg shadow-sm border p-6">
        <div className="text-center">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">Overall Security & Performance Score</h2>
          <div className={`inline-flex items-center justify-center w-32 h-32 rounded-full text-4xl font-bold ${getScoreBg(results.overall_score)} ${getScoreColor(results.overall_score)}`}>
            {results.overall_score}%
          </div>
          <p className="mt-4 text-gray-600">
            {results.overall_score >= 80 ? 'Excellent' :
             results.overall_score >= 60 ? 'Good' :
             results.overall_score >= 40 ? 'Needs Improvement' : 'Critical Issues Found'}
          </p>
        </div>
      </div>

      {/* Test Results Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {results.results.web_testing && (
          <div className="bg-white rounded-lg shadow-sm border p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                <span className="text-blue-600 text-xl">🌐</span>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Web Testing</h3>
                <p className="text-sm text-gray-600">Performance & Functionality</p>
              </div>
            </div>
            <div className={`text-3xl font-bold mb-2 ${getScoreColor(results.results.web_testing.overall_score)}`}>
              {results.results.web_testing.overall_score}%
            </div>
            <div className="space-y-2 text-sm">
              {results.results.web_testing.tests.performance && (
                <div className="flex justify-between">
                  <span>Performance:</span>
                  <span className={getScoreColor(results.results.web_testing.tests.performance.performance_score)}>
                    {results.results.web_testing.tests.performance.performance_score}%
                  </span>
                </div>
              )}
              {results.results.web_testing.tests.seo && (
                <div className="flex justify-between">
                  <span>SEO:</span>
                  <span className={getScoreColor(results.results.web_testing.tests.seo.seo_score)}>
                    {results.results.web_testing.tests.seo.seo_score}%
                  </span>
                </div>
              )}
              {results.results.web_testing.tests.accessibility && (
                <div className="flex justify-between">
                  <span>Accessibility:</span>
                  <span className={getScoreColor(results.results.web_testing.tests.accessibility.accessibility_score)}>
                    {results.results.web_testing.tests.accessibility.accessibility_score}%
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {results.results.security_testing && (
          <div className="bg-white rounded-lg shadow-sm border p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 bg-red-100 rounded-full flex items-center justify-center">
                <span className="text-red-600 text-xl">🔒</span>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Security Testing</h3>
                <p className="text-sm text-gray-600">Vulnerability Assessment</p>
              </div>
            </div>
            <div className={`text-3xl font-bold mb-2 ${getScoreColor(results.results.security_testing.security_score)}`}>
              {results.results.security_testing.security_score}%
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between items-center">
                <span>Risk Level:</span>
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRiskLevelColor(results.results.security_testing.risk_level)}`}>
                  {results.results.security_testing.risk_level}
                </span>
              </div>
              {results.results.security_testing.security_tests?.vulnerabilities?.vulnerabilities && (
                <div className="flex justify-between">
                  <span>Vulnerabilities:</span>
                  <span className="text-red-600 font-medium">
                    {results.results.security_testing.security_tests.vulnerabilities.vulnerabilities.length}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {results.results.aws_audit && (
          <div className="bg-white rounded-lg shadow-sm border p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 bg-orange-100 rounded-full flex items-center justify-center">
                <span className="text-orange-600 text-xl">☁️</span>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900">AWS Audit</h3>
                <p className="text-sm text-gray-600">Cloud Security</p>
              </div>
            </div>
            <div className={`text-3xl font-bold mb-2 ${getScoreColor(results.results.aws_audit.compliance_score)}`}>
              {results.results.aws_audit.compliance_score}%
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span>Compliance:</span>
                <span className={getScoreColor(results.results.aws_audit.compliance_score)}>
                  {results.results.aws_audit.compliance_score}%
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* AI Insights */}
      {results.ai_insights && (
        <div className="bg-white rounded-lg shadow-sm border p-6">
          <div className="flex items-center gap-3 mb-6">
            <div className="w-10 h-10 bg-purple-100 rounded-full flex items-center justify-center">
              <span className="text-purple-600 text-xl">🤖</span>
            </div>
            <div>
              <h3 className="text-xl font-semibold text-gray-900">AI-Powered Insights</h3>
              <p className="text-gray-600">Intelligent analysis and recommendations</p>
            </div>
          </div>

          {results.ai_insights.overall_assessment && (
            <div className="mb-6 p-4 bg-gray-50 rounded-lg">
              <h4 className="font-semibold text-gray-900 mb-2">Overall Assessment</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-600">Overall Grade:</span>
                  <span className="ml-2 font-medium">{results.ai_insights.overall_assessment.overall_grade}</span>
                </div>
                <div>
                  <span className="text-gray-600">Security Maturity:</span>
                  <span className="ml-2 font-medium">{results.ai_insights.overall_assessment.security_maturity}</span>
                </div>
              </div>
            </div>
          )}

          {results.ai_insights.recommendations && results.ai_insights.recommendations.length > 0 && (
            <div>
              <h4 className="font-semibold text-gray-900 mb-4">Top Recommendations</h4>
              <div className="space-y-3">
                {results.ai_insights.recommendations.slice(0, 3).map((rec, index) => (
                  <div key={index} className="border-l-4 border-blue-500 pl-4 py-2">
                    <h5 className="font-medium text-gray-900">{rec.title}</h5>
                    <p className="text-sm text-gray-600 mt-1">{rec.description}</p>
                    <div className="flex gap-4 mt-2 text-xs text-gray-500">
                      <span>Priority: {rec.priority}</span>
                      <span>Impact: {rec.impact}</span>
                      <span>Effort: {rec.effort}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Download Reports */}
      <div className="bg-white rounded-lg shadow-sm border p-6">
        <h3 className="text-xl font-semibold text-gray-900 mb-4">Download Reports</h3>
        <p className="text-gray-600 mb-6">Get detailed reports in your preferred format</p>
        
        <div className="flex flex-wrap gap-4">
          <button
            onClick={() => downloadReport('html')}
            disabled={downloadingReport}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            <span>📄</span>
            HTML Report
          </button>
          
          <button
            onClick={() => downloadReport('pdf')}
            disabled={downloadingReport}
            className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50"
          >
            <span>📋</span>
            PDF Report
          </button>
          
          <button
            onClick={() => downloadReport('json')}
            disabled={downloadingReport}
            className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50"
          >
            <span>💾</span>
            JSON Data
          </button>
        </div>
        
        {downloadingReport && (
          <div className="mt-4 text-sm text-gray-600">
            Generating report...
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex justify-center gap-4">
        <Link
          to="/test"
          className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
        >
          Run New Test
        </Link>
        <Link
          to="/reports"
          className="px-6 py-3 bg-gray-600 text-white rounded-lg hover:bg-gray-700 font-medium"
        >
          View All Reports
        </Link>
      </div>
    </div>
  )
}

export default TestResults

