import React, { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Shield,
  Globe,
  Server,
  Settings,
  Database,
  Network,
  Lock,
  Zap,
  Eye,
  Activity,
  Brain,
  Cpu,
  Sparkles,
} from "lucide-react";

interface TargetSpecificationPanelProps {
  onScanInitiate?: (targetData: {
    targetType: string;
    targetValue: string;
    assessmentProfile: string;
    configOptions: Record<string, any>;
  }) => void;
}

const TargetSpecificationPanel = ({
  onScanInitiate = () => {},
}: TargetSpecificationPanelProps) => {
  const [targetType, setTargetType] = useState("domain");
  const [targetValue, setTargetValue] = useState("");
  const [assessmentProfile, setAssessmentProfile] = useState("rapid");
  const [configOptions, setConfigOptions] = useState<Record<string, any>>({
    rapid: {
      portScan: "top-100",
      webScan: true,
      sslScan: true,
      wafDetection: false,
      advancedDnsRecon: false,
      fullPortScan: false,
      advancedBannerGrab: false,
      cloudHardening: false,
    },
    comprehensive: {
      portScan: "top-1000",
      webScan: true,
      sslScan: true,
      vulnScan: true,
      techFingerprint: true,
      dnsRecon: true,
      subdomainEnum: true,
      webCrawling: true,
      authTesting: true,
      wafDetection: true,
      advancedDnsRecon: true,
      fullPortScan: false,
      advancedBannerGrab: true,
      cloudHardening: true,
    },
    fullPenTest: {
      portScan: "all",
      webScan: true,
      sslScan: true,
      vulnScan: true,
      techFingerprint: true,
      owaspScan: true,
      exploitAnalysis: true,
      riskAssessment: true,
      dnsRecon: true,
      subdomainEnum: true,
      webCrawling: true,
      authTesting: true,
      businessLogicTesting: true,
      sqlInjectionTesting: true,
      xssTesting: true,
      pathTraversalTesting: true,
      realTimeUpdates: true,
      databaseStorage: true,
      apiIntegration: true,
      wafDetection: true,
      advancedDnsRecon: true,
      fullPortScan: true,
      advancedBannerGrab: true,
      cloudHardening: true,
    },
  });

  const handleTargetTypeChange = (value: string) => {
    setTargetType(value);
    setTargetValue("");
  };

  const handleAssessmentProfileChange = (value: string) => {
    setAssessmentProfile(value);
  };

  const handleConfigOptionChange = (
    profile: string,
    option: string,
    value: any,
  ) => {
    setConfigOptions({
      ...configOptions,
      [profile]: {
        ...configOptions[profile],
        [option]: value,
      },
    });
  };

  const handleScanInitiate = () => {
    onScanInitiate({
      targetType,
      targetValue,
      assessmentProfile,
      configOptions: configOptions[assessmentProfile],
    });
  };

  const getTargetPlaceholder = () => {
    switch (targetType) {
      case "ipv4":
        return "192.168.1.1";
      case "ipv6":
        return "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
      case "domain":
        return "example.com";
      default:
        return "Enter target";
    }
  };

  return (
    <Card className="w-full max-w-md scanner-card shadow-[0_0_40px_rgba(0,0,0,0.5)] border border-zinc-800 bg-[#090514]/90 backdrop-blur-xl relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/5 via-transparent to-transparent pointer-events-none" />
      <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-indigo-500 via-fuchsia-400 to-indigo-500" />
      <CardHeader className="bg-[#130A24]/80 border-b border-zinc-800 relative pb-5">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-indigo-900/10 via-transparent to-transparent pointer-events-none" />
        <CardTitle className="flex items-center text-xl font-black tracking-wide text-zinc-100 relative z-10">
          <div className="relative mr-3">
            <Shield className="h-7 w-7 text-indigo-400 floating" />
            <div className="absolute inset-0 h-7 w-7 bg-indigo-400/20 rounded-full animate-ping" style={{ animationDuration: '3s' }} />
          </div>
          <span className="bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-fuchsia-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.3)]">
            Sentinel Core Server
          </span>
        </CardTitle>
        <div className="flex items-center gap-2 mt-3 relative z-10">
          <Badge
            variant="outline"
            className="text-xs text-indigo-700 dark:text-indigo-400 border-indigo-500/50 bg-indigo-100/80 dark:bg-indigo-900/20 backdrop-blur-sm"
          >
            <Activity className="mr-1 h-3 w-3" />
            Automated
          </Badge>
          <Badge
            variant="outline"
            className="text-xs text-fuchsia-700 dark:text-fuchsia-400 border-fuchsia-500/50 bg-fuchsia-100/80 dark:bg-fuchsia-900/20 backdrop-blur-sm"
          >
            <Database className="mr-1 h-3 w-3" />
            SQLite Backend
          </Badge>
          <Badge
            variant="outline"
            className="text-xs text-purple-700 dark:text-purple-400 border-purple-500/50 bg-purple-100/80 dark:bg-purple-900/20 backdrop-blur-sm"
          >
            <Shield className="mr-1 h-3 w-3" />
            Security Audit
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="pt-6 relative">
        <div className="space-y-6">
          <div className="space-y-4">
            <Label className="text-sm font-medium text-indigo-700 dark:text-indigo-300 flex items-center">
              <Eye className="mr-2 h-4 w-4" />
              Target Classification
            </Label>
            <RadioGroup
              value={targetType}
              onValueChange={handleTargetTypeChange}
              className="grid grid-cols-3 gap-3"
            >
              <div className="flex items-center space-x-2 p-3 rounded-lg glass-effect hover:bg-indigo-500/10 transition-all duration-300">
                <RadioGroupItem
                  value="domain"
                  id="domain"
                  className="border-indigo-400"
                />
                <Label
                  htmlFor="domain"
                  className="cursor-pointer flex items-center text-indigo-700 dark:text-indigo-300 font-medium"
                >
                  <Globe className="mr-2 h-4 w-4" /> Domain
                </Label>
              </div>
              <div className="flex items-center space-x-2 p-3 rounded-lg glass-effect hover:bg-fuchsia-500/10 transition-all duration-300">
                <RadioGroupItem
                  value="ipv4"
                  id="ipv4"
                  className="border-fuchsia-400"
                />
                <Label
                  htmlFor="ipv4"
                  className="cursor-pointer flex items-center text-fuchsia-700 dark:text-fuchsia-300 font-medium"
                >
                  <Server className="mr-2 h-4 w-4" /> IPv4
                </Label>
              </div>
              <div className="flex items-center space-x-2 p-3 rounded-lg glass-effect hover:bg-purple-500/10 transition-all duration-300">
                <RadioGroupItem
                  value="ipv6"
                  id="ipv6"
                  className="border-purple-400"
                />
                <Label
                  htmlFor="ipv6"
                  className="cursor-pointer flex items-center text-purple-700 dark:text-purple-300 font-medium"
                >
                  <Server className="mr-2 h-4 w-4" /> IPv6
                </Label>
              </div>
            </RadioGroup>
          </div>

          <div className="space-y-3">
            <Label
              htmlFor="target-input"
              className="text-sm font-medium text-zinc-700 dark:text-zinc-200 flex items-center"
            >
              <Network className="mr-2 h-4 w-4 text-indigo-400" />
              Target{" "}
              {targetType === "domain"
                ? "Domain"
                : targetType === "ipv4"
                  ? "IPv4 Address"
                  : "IPv6 Address"}
            </Label>
            <div className="relative">
              <Input
                id="target-input"
                placeholder={getTargetPlaceholder()}
                value={targetValue}
                onChange={(e) => setTargetValue(e.target.value)}
                className="bg-white/90 dark:bg-zinc-800/50 border-zinc-300 dark:border-zinc-600 text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-500 dark:placeholder:text-zinc-400 focus:border-indigo-500 focus:ring-indigo-500/20 backdrop-blur-sm transition-all duration-300 pl-10"
              />
              <div className="absolute left-3 top-1/2 transform -tranzinc-y-1/2">
                {targetType === "domain" ? (
                  <Globe className="h-4 w-4 text-indigo-400" />
                ) : (
                  <Server className="h-4 w-4 text-fuchsia-400" />
                )}
              </div>
              {targetValue && (
                <div className="absolute right-3 top-1/2 transform -tranzinc-y-1/2">
                  <div className="w-2 h-2 bg-indigo-400 rounded-full animate-pulse" />
                </div>
              )}
            </div>
          </div>

          <div className="space-y-4">
            <Label className="text-sm font-medium">Assessment Profile</Label>
            <Select
              value={assessmentProfile}
              onValueChange={handleAssessmentProfileChange}
            >
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Select profile" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="rapid">Rapid Assessment</SelectItem>
                <SelectItem value="comprehensive">
                  Comprehensive Audit
                </SelectItem>
                <SelectItem value="fullPenTest">
                  Full Penetration Test
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Tabs
            value={assessmentProfile}
            onValueChange={handleAssessmentProfileChange}
            className="w-full"
          >
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="rapid">Rapid</TabsTrigger>
              <TabsTrigger value="comprehensive">Comprehensive</TabsTrigger>
              <TabsTrigger value="fullPenTest">Full Pen Test</TabsTrigger>
            </TabsList>

            <TabsContent value="rapid" className="space-y-4 pt-4">
              <div className="bg-zinc-800/50 p-4 rounded-lg border border-zinc-700">
                <div className="flex items-center gap-2 mb-3">
                  <Zap className="h-4 w-4 text-yellow-400" />
                  <span className="text-sm font-medium text-zinc-200">
                    Quick Assessment Features
                  </span>
                </div>
                <div className="space-y-3">
                  <div className="space-y-2">
                    <Label className="text-sm font-medium text-zinc-300">
                      Port Scan Range
                    </Label>
                    <Select
                      value={configOptions.rapid.portScan}
                      onValueChange={(value) =>
                        handleConfigOptionChange("rapid", "portScan", value)
                      }
                    >
                      <SelectTrigger className="bg-zinc-700 border-zinc-600">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="top-100">Top 100 Ports</SelectItem>
                        <SelectItem value="top-1000">Top 1000 Ports</SelectItem>
                        <SelectItem value="common">Common Ports</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Network className="h-3 w-3" />
                      <span>Basic Port Scan</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Globe className="h-3 w-3" />
                      <span>Web Scanning</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Lock className="h-3 w-3" />
                      <span>SSL/TLS Check</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Shield className="h-3 w-3" />
                      <span>Heuristic Analysis</span>
                    </div>
                    <div className="flex items-center gap-1 text-zinc-400">
                      <Shield className="h-3 w-3" />
                      <span>Basic WAF Detection</span>
                    </div>
                    <div className="flex items-center gap-1 text-zinc-400">
                      <Globe className="h-3 w-3" />
                      <span>Standard DNS Lookup</span>
                    </div>
                  </div>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="comprehensive" className="space-y-4 pt-4">
              <div className="bg-zinc-800/50 p-4 rounded-lg border border-zinc-700">
                <div className="flex items-center gap-2 mb-3">
                  <Eye className="h-4 w-4 text-blue-400" />
                  <span className="text-sm font-medium text-zinc-200">
                    Comprehensive Audit Features
                  </span>
                </div>
                <div className="space-y-3">
                  <div className="space-y-2">
                    <Label className="text-sm font-medium text-zinc-300">
                      Port Scan Range
                    </Label>
                    <Select
                      value={configOptions.comprehensive.portScan}
                      onValueChange={(value) =>
                        handleConfigOptionChange(
                          "comprehensive",
                          "portScan",
                          value,
                        )
                      }
                    >
                      <SelectTrigger className="bg-zinc-700 border-zinc-600">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="top-100">Top 100 Ports</SelectItem>
                        <SelectItem value="top-1000">Top 1000 Ports</SelectItem>
                        <SelectItem value="all">All Ports</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Network className="h-3 w-3" />
                      <span>Full Port Scan</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Globe className="h-3 w-3" />
                      <span>DNS Reconnaissance</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Server className="h-3 w-3" />
                      <span>Tech Fingerprinting</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Database className="h-3 w-3" />
                      <span>Vulnerability Scan</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Lock className="h-3 w-3" />
                      <span>Auth Testing</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Activity className="h-3 w-3" />
                      <span>Web Crawling</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Shield className="h-3 w-3" />
                      <span>Advanced Analysis</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Activity className="h-3 w-3" />
                      <span>Threat Detection</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Shield className="h-3 w-3" />
                      <span>Advanced WAF Detection</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Globe className="h-3 w-3" />
                      <span>Advanced DNS Recon</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Server className="h-3 w-3" />
                      <span>Advanced Banner Grab</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <Database className="h-3 w-3" />
                      <span>Cloud Hardening Check</span>
                    </div>
                  </div>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="fullPenTest" className="space-y-4 pt-4">
              <div className="bg-gradient-to-br from-red-900/20 to-purple-900/20 p-4 rounded-lg border border-red-800/30">
                <div className="flex items-center gap-2 mb-3">
                  <Shield className="h-4 w-4 text-red-400" />
                  <span className="text-sm font-medium text-zinc-200">
                    Full Penetration Test Suite
                  </span>
                </div>
                <div className="space-y-3">
                  <div className="space-y-2">
                    <Label className="text-sm font-medium text-zinc-300">
                      OWASP Scan Depth
                    </Label>
                    <Select
                      value={
                        configOptions.fullPenTest.owaspScan ? "full" : "basic"
                      }
                      onValueChange={(value) =>
                        handleConfigOptionChange(
                          "fullPenTest",
                          "owaspScan",
                          value === "full",
                        )
                      }
                    >
                      <SelectTrigger className="bg-zinc-700 border-zinc-600">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="basic">Basic (Top 5)</SelectItem>
                        <SelectItem value="full">Full (Top 10)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid grid-cols-2 gap-1 text-xs">
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ SQL Injection Testing</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ XSS Testing</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Path Traversal</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Business Logic</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Real-time Updates</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ REST API</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Enterprise Analysis</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Heuristic Engine</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Statistical Analysis</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Exploit Prediction</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ WebSocket Support</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Risk Assessment</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Advanced WAF/Firewall Detection</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Full Port Scanning (65535)</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Advanced DNS Reconnaissance</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Advanced Banner Grabbing</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Cloud Hardening Assessment</span>
                    </div>
                    <div className="flex items-center gap-1 text-indigo-400">
                      <span>✓ Infrastructure Security Analysis</span>
                    </div>
                  </div>
                  <div className="mt-3 p-2 bg-amber-900/20 border border-amber-700/30 rounded">
                    <p className="text-xs text-amber-300">
                      <Shield className="inline h-3 w-3 mr-1" />
                      Protected against private IP scanning
                    </p>
                  </div>
                </div>
              </div>
            </TabsContent>
          </Tabs>

          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-zinc-400">
              <span>Scan Features:</span>
              <span className="text-indigo-400">
                {assessmentProfile === "rapid"
                  ? "6"
                  : assessmentProfile === "comprehensive"
                    ? "12"
                    : "18"}{" "}
                modules
              </span>
            </div>
            <Progress
              value={
                assessmentProfile === "rapid"
                  ? 33
                  : assessmentProfile === "comprehensive"
                    ? 66
                    : 100
              }
              className="h-2"
            />
            <Button
              onClick={handleScanInitiate}
              variant="scanner"
              size="lg"
              className="w-full relative overflow-hidden group"
              disabled={!targetValue.trim()}
            >
              <div className="absolute inset-0 bg-gradient-to-r from-indigo-600 to-fuchsia-600 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
              <div className="relative z-10 flex items-center justify-center">
                <Shield className="mr-3 h-6 w-6" />
                <span className="font-bold text-lg">START VAPT SCAN</span>
                <Zap className="ml-3 h-6 w-6" />
              </div>
              {!targetValue.trim() && (
                <div className="absolute inset-0 bg-zinc-700/50 backdrop-blur-sm" />
              )}
            </Button>
            <div className="grid grid-cols-3 gap-2 text-xs text-center">
              <div className="text-zinc-400">
                <Database className="h-3 w-3 mx-auto mb-1" />
                <span>SQLite DB</span>
              </div>
              <div className="text-zinc-400">
                <Activity className="h-3 w-3 mx-auto mb-1" />
                <span>Real-time</span>
              </div>
              <div className="text-zinc-400">
                <Network className="h-3 w-3 mx-auto mb-1" />
                <span>REST API</span>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default TargetSpecificationPanel;
