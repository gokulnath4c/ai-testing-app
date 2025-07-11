import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

const TestConfiguration = () => {
  const navigate = useNavigate()
  const [url, setUrl] = useState('')
  const [testTypes, setTestTypes] = useState({
    web: true,
    security: true,
    aws: false
  })
  const [awsConfig, setAwsConfig] = useState({
    accessKey: '',
    secretKey: '',
    region: 'us-east-1'
  })
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')

  const isValidUrl = (string) => {
    try {
      new URL(string)
      return true
    } catch (_) {
      return false
    }
  }

  const handleTestTypeChange = (type) => {
    setTestTypes(prev => ({
      ...prev,
      [type]: !prev[type]
    }))
  }

  const handleStartTest = async () => {
    if (!url || !isValidUrl(url)) {
      setError('Please enter a valid URL')
      return
    }

    const selectedTypes = Object.keys(testTypes).filter(type => testTypes[type])
    if (selectedTypes.length === 0) {
      setError('Please select at least one test type')
      return
    }

    setIsLoading(true)
    setError('')

    try {
      const response = await fetch('http://localhost:5000/api/test/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: url,
          test_types: selectedTypes,
          aws_config: testTypes.aws ? awsConfig : undefined
        })
      })

      const data = await response.json()

      if (data.error) {
        setError(data.error)
      } else if (data.test_id) {
        // Navigate to results page with test ID
        navigate(`/results/${data.test_id}`)
      }
    } catch (err) {
      setError('Failed to start test. Please check your connection.')
    } finally {
      setIsLoading(false)
    }
  }

  const selectedTestTypes = Object.keys(testTypes).filter(type => testTypes[type])

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-8">
      <div className="text-center">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Configure New Test</h1>
        <p className="text-gray-600">Set up comprehensive testing for your website or application</p>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <p className="text-red-800">{error}</p>
        </div>
      )}

      {/* Target URL */}
      <div className="bg-white rounded-lg shadow-sm border p-6">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
            <span className="text-blue-600 font-semibold">🌐</span>
          </div>
          <h2 className="text-xl font-semibold text-gray-900">Target URL</h2>
        </div>
        <p className="text-gray-600 mb-4">Enter the website or application URL you want to test</p>
        
        <div className="space-y-2">
          <label htmlFor="url" className="block text-sm font-medium text-gray-700">
            Website URL
          </label>
          <input
            id="url"
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
          {url && isValidUrl(url) && (
            <div className="flex items-center gap-2 text-green-600 text-sm">
              <span>✓</span>
              <span>Valid URL</span>
            </div>
          )}
        </div>
      </div>

      {/* Test Types */}
      <div className="bg-white rounded-lg shadow-sm border p-6">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-8 h-8 bg-purple-100 rounded-full flex items-center justify-center">
            <span className="text-purple-600 font-semibold">⚙️</span>
          </div>
          <h2 className="text-xl font-semibold text-gray-900">Test Types</h2>
        </div>
        <p className="text-gray-600 mb-6">Select the types of tests you want to perform</p>

        <div className="space-y-4">
          <div className="flex items-start gap-3">
            <input
              type="checkbox"
              id="web-testing"
              checked={testTypes.web}
              onChange={() => handleTestTypeChange('web')}
              className="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <div className="flex-1">
              <label htmlFor="web-testing" className="block text-sm font-medium text-gray-900">
                🌐 Web Application Testing
              </label>
              <p className="text-sm text-gray-600">Performance, SEO, accessibility, and functionality testing</p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <input
              type="checkbox"
              id="security-testing"
              checked={testTypes.security}
              onChange={() => handleTestTypeChange('security')}
              className="mt-1 h-4 w-4 text-red-600 focus:ring-red-500 border-gray-300 rounded"
            />
            <div className="flex-1">
              <label htmlFor="security-testing" className="block text-sm font-medium text-gray-900">
                🔒 Security Testing
              </label>
              <p className="text-sm text-gray-600">Vulnerability scanning, penetration testing, and security analysis</p>
            </div>
          </div>
        </div>
      </div>

      {/* AWS Security Audit */}
      <div className="bg-white rounded-lg shadow-sm border p-6">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-8 h-8 bg-orange-100 rounded-full flex items-center justify-center">
            <span className="text-orange-600 font-semibold">☁️</span>
          </div>
          <h2 className="text-xl font-semibold text-gray-900">AWS Security Audit</h2>
        </div>
        <p className="text-gray-600 mb-4">Optional: Audit your AWS infrastructure security and compliance</p>

        <div className="flex items-start gap-3 mb-4">
          <input
            type="checkbox"
            id="aws-audit"
            checked={testTypes.aws}
            onChange={() => handleTestTypeChange('aws')}
            className="mt-1 h-4 w-4 text-orange-600 focus:ring-orange-500 border-gray-300 rounded"
          />
          <label htmlFor="aws-audit" className="block text-sm font-medium text-gray-900">
            Enable AWS Security Audit
          </label>
        </div>

        {testTypes.aws && (
          <div className="space-y-4 mt-4 p-4 bg-gray-50 rounded-lg">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                AWS Access Key ID
              </label>
              <input
                type="text"
                value={awsConfig.accessKey}
                onChange={(e) => setAwsConfig(prev => ({ ...prev, accessKey: e.target.value }))}
                placeholder="AKIA..."
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                AWS Secret Access Key
              </label>
              <input
                type="password"
                value={awsConfig.secretKey}
                onChange={(e) => setAwsConfig(prev => ({ ...prev, secretKey: e.target.value }))}
                placeholder="••••••••••••••••••••••••••••••••••••••••"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                AWS Region
              </label>
              <select
                value={awsConfig.region}
                onChange={(e) => setAwsConfig(prev => ({ ...prev, region: e.target.value }))}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500"
              >
                <option value="us-east-1">US East (N. Virginia)</option>
                <option value="us-west-2">US West (Oregon)</option>
                <option value="eu-west-1">Europe (Ireland)</option>
                <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Test Summary */}
      <div className="bg-white rounded-lg shadow-sm border p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Test Summary</h3>
        <p className="text-gray-600 mb-4">Review your test configuration</p>

        <div className="space-y-3">
          <div>
            <span className="text-sm font-medium text-gray-700">Target URL</span>
            <p className="text-gray-900">{url || 'Not specified'}</p>
          </div>
          
          <div>
            <span className="text-sm font-medium text-gray-700">Selected Tests</span>
            <div className="flex flex-wrap gap-2 mt-1">
              {selectedTestTypes.map(type => (
                <span
                  key={type}
                  className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    type === 'web' ? 'bg-blue-100 text-blue-800' :
                    type === 'security' ? 'bg-red-100 text-red-800' :
                    'bg-orange-100 text-orange-800'
                  }`}
                >
                  {type === 'web' ? '🌐 Web Testing' :
                   type === 'security' ? '🔒 Security Testing' :
                   '☁️ AWS Audit'}
                </span>
              ))}
            </div>
          </div>
        </div>

        <button
          onClick={handleStartTest}
          disabled={isLoading || !url || !isValidUrl(url) || selectedTestTypes.length === 0}
          className="w-full mt-6 bg-gradient-to-r from-blue-600 to-purple-600 text-white py-3 px-6 rounded-lg font-semibold hover:from-blue-700 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
        >
          {isLoading ? (
            <div className="flex items-center justify-center gap-2">
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              Starting Test...
            </div>
          ) : (
            <div className="flex items-center justify-center gap-2">
              <span>▶</span>
              Start Test
            </div>
          )}
        </button>
      </div>

      {/* Estimated Duration */}
      <div className="bg-gray-50 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Estimated Duration</h3>
        
        <div className="space-y-2 text-sm">
          {testTypes.web && (
            <div className="flex justify-between">
              <span>Web Testing:</span>
              <span className="font-medium">2-5 minutes</span>
            </div>
          )}
          {testTypes.security && (
            <div className="flex justify-between">
              <span>Security Testing:</span>
              <span className="font-medium">5-10 minutes</span>
            </div>
          )}
          {testTypes.aws && (
            <div className="flex justify-between">
              <span>AWS Audit:</span>
              <span className="font-medium">3-8 minutes</span>
            </div>
          )}
          <div className="border-t pt-2 flex justify-between font-semibold">
            <span>Total:</span>
            <span>
              {testTypes.web && testTypes.security && testTypes.aws ? '10-23 minutes' :
               testTypes.web && testTypes.security ? '7-15 minutes' :
               testTypes.web && testTypes.aws ? '5-13 minutes' :
               testTypes.security && testTypes.aws ? '8-18 minutes' :
               testTypes.web ? '2-5 minutes' :
               testTypes.security ? '5-10 minutes' :
               testTypes.aws ? '3-8 minutes' : '0 minutes'}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

export default TestConfiguration

