import { useState } from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { Toaster } from '@/components/ui/toaster'
import Header from '@/components/Header'
import Dashboard from '@/components/Dashboard'
import TestConfiguration from '@/components/TestConfiguration'
import TestResults from '@/components/TestResults'
import Reports from '@/components/Reports'
import './App.css'

function App() {
  const [currentTest, setCurrentTest] = useState(null)

  return (
    <Router>
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
        <Header />
        <main className="container mx-auto px-4 py-8">
          <Routes>
            <Route 
              path="/" 
              element={<Dashboard currentTest={currentTest} setCurrentTest={setCurrentTest} />} 
            />
            <Route 
              path="/test" 
              element={<TestConfiguration setCurrentTest={setCurrentTest} />} 
            />
            <Route 
              path="/results/:testId" 
              element={<TestResults />} 
            />
            <Route 
              path="/reports" 
              element={<Reports />} 
            />
          </Routes>
        </main>
        <Toaster />
      </div>
    </Router>
  )
}

export default App

