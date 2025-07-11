import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { 
  FileText, 
  Download, 
  Calendar, 
  Filter,
  Search,
  Eye,
  Trash2,
  MoreHorizontal
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { 
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger
} from '@/components/ui/dropdown-menu'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

const Reports = () => {
  const [reports, setReports] = useState([])
  const [filteredReports, setFilteredReports] = useState([])
  const [searchTerm, setSearchTerm] = useState('')
  const [filterType, setFilterType] = useState('all')
  const [sortBy, setSortBy] = useState('date')

  useEffect(() => {
    // Simulate loading reports
    const mockReports = [
      {
        id: 'test_20250108_143022',
        url: 'https://example.com',
        date: '2025-01-08T14:30:22Z',
        type: 'Full Audit',
        score: 85,
        status: 'completed',
        testTypes: ['web', 'security'],
        size: '2.3 MB',
        downloads: 12
      },
      {
        id: 'test_20250108_120015',
        url: 'https://demo.website.com',
        date: '2025-01-08T12:00:15Z',
        type: 'Security Only',
        score: 72,
        status: 'completed',
        testTypes: ['security'],
        size: '1.8 MB',
        downloads: 8
      },
      {
        id: 'test_20250107_165530',
        url: 'https://testsite.org',
        date: '2025-01-07T16:55:30Z',
        type: 'Web + AWS',
        score: 91,
        status: 'completed',
        testTypes: ['web', 'aws'],
        size: '3.1 MB',
        downloads: 15
      },
      {
        id: 'test_20250107_094422',
        url: 'https://myapp.io',
        date: '2025-01-07T09:44:22Z',
        type: 'Full Audit',
        score: 68,
        status: 'completed',
        testTypes: ['web', 'security', 'aws'],
        size: '4.2 MB',
        downloads: 23
      },
      {
        id: 'test_20250106_133015',
        url: 'https://portfolio.dev',
        date: '2025-01-06T13:30:15Z',
        type: 'Web Only',
        score: 94,
        status: 'completed',
        testTypes: ['web'],
        size: '1.2 MB',
        downloads: 5
      }
    ]
    setReports(mockReports)
    setFilteredReports(mockReports)
  }, [])

  useEffect(() => {
    let filtered = reports

    // Apply search filter
    if (searchTerm) {
      filtered = filtered.filter(report => 
        report.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
        report.id.toLowerCase().includes(searchTerm.toLowerCase())
      )
    }

    // Apply type filter
    if (filterType !== 'all') {
      filtered = filtered.filter(report => {
        switch (filterType) {
          case 'web':
            return report.testTypes.includes('web')
          case 'security':
            return report.testTypes.includes('security')
          case 'aws':
            return report.testTypes.includes('aws')
          case 'full':
            return report.testTypes.length >= 2
          default:
            return true
        }
      })
    }

    // Apply sorting
    filtered.sort((a, b) => {
      switch (sortBy) {
        case 'date':
          return new Date(b.date) - new Date(a.date)
        case 'score':
          return b.score - a.score
        case 'url':
          return a.url.localeCompare(b.url)
        case 'downloads':
          return b.downloads - a.downloads
        default:
          return 0
      }
    })

    setFilteredReports(filtered)
  }, [reports, searchTerm, filterType, sortBy])

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-600 bg-green-50'
    if (score >= 60) return 'text-yellow-600 bg-yellow-50'
    return 'text-red-600 bg-red-50'
  }

  const getTypeColor = (testTypes) => {
    if (testTypes.length >= 3) return 'bg-purple-100 text-purple-800'
    if (testTypes.includes('security')) return 'bg-red-100 text-red-800'
    if (testTypes.includes('aws')) return 'bg-green-100 text-green-800'
    return 'bg-blue-100 text-blue-800'
  }

  const downloadReport = async (reportId, format) => {
    try {
      const response = await fetch(`/api/test/report/${reportId}?format=${format}`)
      const data = await response.json()
      
      if (response.ok && data.download_url) {
        window.open(data.download_url, '_blank')
        
        // Update download count
        setReports(prev => prev.map(report => 
          report.id === reportId 
            ? { ...report, downloads: report.downloads + 1 }
            : report
        ))
      }
    } catch (err) {
      console.error('Failed to download report:', err)
    }
  }

  const deleteReport = (reportId) => {
    setReports(prev => prev.filter(report => report.id !== reportId))
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Reports</h1>
          <p className="text-lg text-gray-600">
            Manage and download your testing reports
          </p>
        </div>
        <Link to="/test">
          <Button>
            <FileText className="h-4 w-4 mr-2" />
            New Test
          </Button>
        </Link>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Reports</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{reports.length}</div>
            <p className="text-xs text-muted-foreground">
              Generated reports
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Average Score</CardTitle>
            <Calendar className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {Math.round(reports.reduce((sum, r) => sum + r.score, 0) / reports.length) || 0}%
            </div>
            <p className="text-xs text-muted-foreground">
              Across all tests
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Downloads</CardTitle>
            <Download className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {reports.reduce((sum, r) => sum + r.downloads, 0)}
            </div>
            <p className="text-xs text-muted-foreground">
              Report downloads
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">This Week</CardTitle>
            <Calendar className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {reports.filter(r => {
                const reportDate = new Date(r.date)
                const weekAgo = new Date()
                weekAgo.setDate(weekAgo.getDate() - 7)
                return reportDate > weekAgo
              }).length}
            </div>
            <p className="text-xs text-muted-foreground">
              New reports
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Filters and Search */}
      <Card>
        <CardHeader>
          <CardTitle>Filter Reports</CardTitle>
          <CardDescription>
            Search and filter your testing reports
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="Search by URL or test ID..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            
            <Select value={filterType} onValueChange={setFilterType}>
              <SelectTrigger className="w-full md:w-48">
                <SelectValue placeholder="Filter by type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="web">Web Testing</SelectItem>
                <SelectItem value="security">Security Testing</SelectItem>
                <SelectItem value="aws">AWS Audit</SelectItem>
                <SelectItem value="full">Full Audit</SelectItem>
              </SelectContent>
            </Select>

            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger className="w-full md:w-48">
                <SelectValue placeholder="Sort by" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="date">Date (Newest)</SelectItem>
                <SelectItem value="score">Score (Highest)</SelectItem>
                <SelectItem value="url">URL (A-Z)</SelectItem>
                <SelectItem value="downloads">Downloads</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Reports List */}
      <Card>
        <CardHeader>
          <CardTitle>Reports ({filteredReports.length})</CardTitle>
          <CardDescription>
            Your testing reports and analysis
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {filteredReports.map((report) => (
              <div key={report.id} className="flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50 transition-colors">
                <div className="flex items-center space-x-4 flex-1">
                  <div className={`w-12 h-12 rounded-lg flex items-center justify-center font-bold text-lg ${getScoreColor(report.score)}`}>
                    {report.score}
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2 mb-1">
                      <h3 className="font-medium truncate">{report.url}</h3>
                      <Badge className={getTypeColor(report.testTypes)}>
                        {report.type}
                      </Badge>
                    </div>
                    <div className="flex items-center space-x-4 text-sm text-gray-500">
                      <span>{new Date(report.date).toLocaleDateString()}</span>
                      <span>{report.size}</span>
                      <span>{report.downloads} downloads</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <Link to={`/results/${report.id}`}>
                    <Button variant="outline" size="sm">
                      <Eye className="h-4 w-4 mr-2" />
                      View
                    </Button>
                  </Link>

                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" size="sm">
                        <Download className="h-4 w-4 mr-2" />
                        Download
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent>
                      <DropdownMenuItem onClick={() => downloadReport(report.id, 'pdf')}>
                        Download PDF
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => downloadReport(report.id, 'html')}>
                        Download HTML
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => downloadReport(report.id, 'json')}>
                        Download JSON
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>

                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="sm">
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent>
                      <DropdownMenuItem onClick={() => deleteReport(report.id)}>
                        <Trash2 className="h-4 w-4 mr-2" />
                        Delete Report
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>
            ))}

            {filteredReports.length === 0 && (
              <div className="text-center py-12">
                <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">No reports found</h3>
                <p className="text-gray-500 mb-4">
                  {searchTerm || filterType !== 'all' 
                    ? 'Try adjusting your search or filter criteria'
                    : 'Start by running your first test to generate reports'
                  }
                </p>
                <Link to="/test">
                  <Button>
                    <FileText className="h-4 w-4 mr-2" />
                    Create New Test
                  </Button>
                </Link>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

export default Reports

