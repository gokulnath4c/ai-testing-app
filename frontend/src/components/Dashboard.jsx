import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { 
  Shield, 
  Globe, 
  Cloud, 
  Activity, 
  TrendingUp, 
  AlertTriangle,
  CheckCircle,
  Clock,
  Plus
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'

const Dashboard = ({ currentTest, setCurrentTest }) => {
  const [recentTests, setRecentTests] = useState([])
  const [stats, setStats] = useState({
    totalTests: 0,
    criticalIssues: 0,
    averageScore: 0,
    testsThisMonth: 0
  })

  useEffect(() => {
    // Simulate loading recent tests and stats
    setRecentTests([
      {
        id: 'test_20250108_143022',
        url: 'https://example.com',
        status: 'completed',
        score: 85,
        timestamp: '2025-01-08T14:30:22Z',
        issues: { critical: 0, high: 2, medium: 5 }
      },
      {
        id: 'test_20250108_120015',
        url: 'https://demo.website.com',
        status: 'completed',
        score: 72,
        timestamp: '2025-01-08T12:00:15Z',
        issues: { critical: 1, high: 3, medium: 8 }
      },
      {
        id: 'test_20250108_095530',
        url: 'https://testsite.org',
        status: 'running',
        score: null,
        timestamp: '2025-01-08T09:55:30Z',
        issues: null
      }
    ])

    setStats({
      totalTests: 47,
      criticalIssues: 3,
      averageScore: 78,
      testsThisMonth: 12
    })
  }, [])

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'running':
        return <Clock className="h-4 w-4 text-blue-500" />
      case 'failed':
        return <AlertTriangle className="h-4 w-4 text-red-500" />
      default:
        return <Clock className="h-4 w-4 text-gray-500" />
    }
  }

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-600'
    if (score >= 60) return 'text-yellow-600'
    return 'text-red-600'
  }

  return (
    <div className="space-y-8">
      {/* Hero Section */}
      <div className="text-center space-y-4">
        <h1 className="text-4xl font-bold text-gray-900">
          AI-Powered Security & Performance Testing
        </h1>
        <p className="text-xl text-gray-600 max-w-3xl mx-auto">
          Comprehensive automated testing for websites and applications. 
          Get instant security assessments, performance insights, and AWS compliance audits.
        </p>
        <Link to="/test">
          <Button size="lg" className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700">
            <Plus className="h-5 w-5 mr-2" />
            Start New Test
          </Button>
        </Link>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Tests</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalTests}</div>
            <p className="text-xs text-muted-foreground">
              +{stats.testsThisMonth} this month
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.criticalIssues}</div>
            <p className="text-xs text-muted-foreground">
              Require immediate attention
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Average Score</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.averageScore}%</div>
            <Progress value={stats.averageScore} className="mt-2" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">This Month</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.testsThisMonth}</div>
            <p className="text-xs text-muted-foreground">
              Tests completed
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Feature Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="hover:shadow-lg transition-shadow">
          <CardHeader>
            <div className="flex items-center space-x-2">
              <div className="bg-blue-100 p-2 rounded-lg">
                <Globe className="h-6 w-6 text-blue-600" />
              </div>
              <div>
                <CardTitle>Web Application Testing</CardTitle>
                <CardDescription>End-to-end functional and performance testing</CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-gray-600">
              <li>• Performance optimization analysis</li>
              <li>• SEO and accessibility audits</li>
              <li>• Cross-browser compatibility</li>
              <li>• Mobile responsiveness testing</li>
            </ul>
          </CardContent>
        </Card>

        <Card className="hover:shadow-lg transition-shadow">
          <CardHeader>
            <div className="flex items-center space-x-2">
              <div className="bg-red-100 p-2 rounded-lg">
                <Shield className="h-6 w-6 text-red-600" />
              </div>
              <div>
                <CardTitle>Security Testing</CardTitle>
                <CardDescription>Comprehensive penetration testing and vulnerability scanning</CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-gray-600">
              <li>• SQL injection detection</li>
              <li>• XSS vulnerability scanning</li>
              <li>• SSL/TLS configuration analysis</li>
              <li>• Security headers validation</li>
            </ul>
          </CardContent>
        </Card>

        <Card className="hover:shadow-lg transition-shadow">
          <CardHeader>
            <div className="flex items-center space-x-2">
              <div className="bg-green-100 p-2 rounded-lg">
                <Cloud className="h-6 w-6 text-green-600" />
              </div>
              <div>
                <CardTitle>AWS Security Audit</CardTitle>
                <CardDescription>Cloud infrastructure security and compliance assessment</CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-gray-600">
              <li>• IAM policy analysis</li>
              <li>• S3 bucket security review</li>
              <li>• EC2 configuration audit</li>
              <li>• Compliance reporting</li>
            </ul>
          </CardContent>
        </Card>
      </div>

      {/* Recent Tests */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Tests</CardTitle>
          <CardDescription>Your latest security and performance assessments</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {recentTests.map((test) => (
              <div key={test.id} className="flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50 transition-colors">
                <div className="flex items-center space-x-4">
                  {getStatusIcon(test.status)}
                  <div>
                    <p className="font-medium">{test.url}</p>
                    <p className="text-sm text-gray-500">
                      {new Date(test.timestamp).toLocaleString()}
                    </p>
                  </div>
                </div>
                
                <div className="flex items-center space-x-4">
                  {test.status === 'completed' && (
                    <>
                      <div className="text-right">
                        <p className={`font-bold ${getScoreColor(test.score)}`}>
                          {test.score}%
                        </p>
                        <div className="flex space-x-1">
                          {test.issues.critical > 0 && (
                            <Badge variant="destructive" className="text-xs">
                              {test.issues.critical} Critical
                            </Badge>
                          )}
                          {test.issues.high > 0 && (
                            <Badge variant="secondary" className="text-xs">
                              {test.issues.high} High
                            </Badge>
                          )}
                        </div>
                      </div>
                      <Link to={`/results/${test.id}`}>
                        <Button variant="outline" size="sm">
                          View Results
                        </Button>
                      </Link>
                    </>
                  )}
                  
                  {test.status === 'running' && (
                    <Badge variant="outline">Running...</Badge>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

export default Dashboard

