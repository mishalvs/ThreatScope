"use client";

import {
  Box,
  Text,
  Badge,
  Button,
  SimpleGrid,
  VStack,
  HStack,
  Divider,
  Spinner,
  Center,
  useToast,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import ThreatSpeedometer from "@/components/ThreatSpeedometer";

export default function ResultPage() {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const toast = useToast();

  useEffect(() => {
    const data = localStorage.getItem("lastScan");
    if (data) setScan(JSON.parse(data));
  }, []);

  if (!scan) {
    return (
      <Center p={10} flexDirection="column">
        <Text>No scan data found.</Text>
        <Button mt={4} onClick={() => router.push("/")}>
          Back to Dashboard
        </Button>
      </Center>
    );
  }

  const results = scan.results || [];
  const threatPercent = scan.threat_score || 0;
  const riskCategory = scan.threat_category || "Low";

  const SpinnerOverlay = () =>
    loading ? (
      <Box
        position="fixed"
        inset={0}
        bg="rgba(0,0,0,0.6)"
        zIndex={9999}
        display="flex"
        alignItems="center"
        justifyContent="center"
      >
        <VStack spacing={4}>
          <Spinner size="xl" thickness="4px" color="blue.400" />
          <Text color="white" fontSize="lg">
            Scanning endpoint...
          </Text>
        </VStack>
      </Box>
    ) : null;

  const generatePDF = async () => {
    try {
      const { default: jsPDF } = await import("jspdf");
      const autoTableModule = await import("jspdf-autotable");
      const doc = new jsPDF();

      doc.setFontSize(18);
      doc.text("Endpoint Security Report", 14, 20);
      doc.setFontSize(12);
      doc.text(`Device: ${scan.device}`, 14, 30);
      doc.text(`OS: ${scan.os}`, 14, 36);
      doc.text(`User: ${scan.username || "N/A"}`, 14, 42);
      doc.text(`Scan Date: ${scan.date}`, 14, 48);
      doc.text(`Risk Category: ${riskCategory}`, 14, 54);

      const tableColumn = ["Check", "Severity", "Recommendation", "CVSS", "Details"];
      const tableRows = results.map((r) => [
        r.check,
        r.severity || "N/A",
        r.recommendation || r.recommendation_text || "Review manually",
        r.cvss_score !== undefined ? r.cvss_score : "N/A",
        r.details || "N/A",
      ]);

      autoTableModule.default(doc, {
        startY: 62,
        head: [tableColumn],
        body: tableRows,
        styles: { fontSize: 10, cellPadding: 3 },
        headStyles: { fillColor: [41, 128, 185], textColor: 255, halign: "center" },
        alternateRowStyles: { fillColor: [245, 245, 245] },
        columnStyles: { 0: { cellWidth: 50 }, 1: { cellWidth: 20 }, 2: { cellWidth: 50 }, 3: { cellWidth: 15 }, 4: { cellWidth: 55 } },
      });

      doc.save(`${scan.device}_security_report.pdf`);
      toast({
        title: "PDF Generated",
        description: "Download should start automatically.",
        status: "success",
        duration: 3000,
        isClosable: true,
      });
    } catch (err) {
      console.error(err);
      toast({
        title: "Error",
        description: "Failed to generate PDF",
        status: "error",
        duration: 3000,
        isClosable: true,
      });
    }
  };

  const getSeverityColor = (severity) => {
    if (severity === "High" || severity === "Critical") return "red.400";
    if (severity === "Medium") return "orange.400";
    if (severity === "Low") return "green.400";
    return "gray.400";
  };

  return (
    <Box bg="gray.50" minH="100vh" py={10}>
      {SpinnerOverlay()}

      <Box maxW="1300px" mx="auto" px={6}>
        {/* Header */}
        <Box bg="white" borderRadius="2xl" shadow="md" p={6} mb={8}>
          <HStack justify="space-between">
            <Box>
              <Text fontSize="2xl" fontWeight="bold" color="gray.800">
                Endpoint Scan Report
              </Text>
              <Text fontSize="sm" color="gray.500">
                {scan.device} • {scan.os.toUpperCase()}
              </Text>
            </Box>
            <Badge
              px={4}
              py={2}
              fontSize="md"
              borderRadius="full"
              colorScheme={
                riskCategory === "Critical"
                  ? "red"
                  : riskCategory === "High"
                  ? "orange"
                  : riskCategory === "Medium"
                  ? "yellow"
                  : "green"
              }
            >
              {riskCategory}
            </Badge>
          </HStack>

          <Divider my={4} />

          {/* Executive Summary */}
          <SimpleGrid columns={[1, 2, 4]} spacing={6}>
            {[
              { label: "TOTAL CHECKS", value: results.length },
              { label: "OVERALL THREAT", value: threatPercent + "%" },
              { label: "RISK LEVEL", value: riskCategory },
            ].map((metric, idx) => (
              <Box
                key={idx}
                bg="gray.50"
                p={4}
                borderRadius="xl"
                shadow="sm"
                textAlign="center"
              >
                <Text fontSize="xs" color="gray.500">
                  {metric.label}
                </Text>
                <Text fontWeight="700" fontSize="lg">
                  {metric.value}
                </Text>
              </Box>
            ))}
          </SimpleGrid>
        </Box>

        {/* Main Grid */}
        <SimpleGrid columns={[1, 2]} spacing={8}>
          {/* Threat Meter */}
          <Box bg="white" borderRadius="2xl" shadow="md" p={8} textAlign="center">
            <ThreatSpeedometer value={threatPercent} />
            <Text mt={4} fontWeight="bold" color="gray.700">
              Threat Level: {threatPercent}%
            </Text>
          </Box>

          {/* Findings & Recommendations */}
          <Box bg="white" borderRadius="2xl" shadow="md" p={6} maxH="600px" overflowY="auto">
            <Text fontWeight="bold" mb={4} fontSize="xl">
              Findings & Recommendations
            </Text>

            <Accordion allowMultiple>
              {results.map((r, i) => (
                <AccordionItem
                  key={i}
                  border="1px solid"
                  borderColor="gray.200"
                  borderRadius="xl"
                  mb={3}
                >
                  <AccordionButton
                    _expanded={{ bg: getSeverityColor(r.severity), color: "white" }}
                  >
                    <Box flex="1" textAlign="left">
                      {r.check} [{r.severity || "N/A"}]
                    </Box>
                    <AccordionIcon />
                  </AccordionButton>
                  <AccordionPanel pb={4}>
                    {r.details && (
                      <Text fontSize="sm" color="gray.600" mb={2}>
                        {r.details}
                      </Text>
                    )}
                    <Text fontSize="sm" color="blue.600">
                      Recommendation: {r.recommendation || r.recommendation_text || "Review manually"}
                    </Text>
                  </AccordionPanel>
                </AccordionItem>
              ))}
            </Accordion>
          </Box>
        </SimpleGrid>

        {/* Download PDF / JSON */}
        <Box mt={10} display="flex" gap={4}>
          <Button colorScheme="blue" onClick={generatePDF}>
            Download PDF Report
          </Button>
          {scan.report_file && (
            <Button
              as="a"
              href={`http://localhost:8000/${scan.report_file}`}
              download
              colorScheme="green"
            >
              Download Backend JSON
            </Button>
          )}
        </Box>
      </Box>
    </Box>
  );
}
