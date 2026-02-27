"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  Box,
  Text,
  VStack,
  HStack,
  Spinner,
  Center,
  Badge,
  Divider,
  Button,
  useToast,
} from "@chakra-ui/react";

export default function ScanDetailsPage() {
  const { id } = useParams();
  const router = useRouter();
  const toast = useToast();

  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);

  const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  useEffect(() => {
    const fetchScan = async () => {
      try {
        if (!id) return;

        const res = await fetch(`${API_URL}/scans/${Number(id)}`);
        if (!res.ok) throw new Error("Scan not found");

        const data = await res.json();
        setScan(data);
      } catch (err) {
        console.error("Error fetching scan:", err);
        setScan({ error: true });
      } finally {
        setLoading(false);
      }
    };

    fetchScan();
  }, [id]);

  // PDF download from backend
  const downloadPDF = async () => {
    try {
      const res = await fetch(`${API_URL}/download_pdf/${id}`);
      if (!res.ok) throw new Error("Failed to download PDF");

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `scan_${id}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();

      toast({
        title: "PDF downloaded",
        description: "Download should start automatically",
        status: "success",
        duration: 3000,
        isClosable: true,
      });
    } catch (err) {
      console.error(err);
      toast({
        title: "Download failed",
        status: "error",
        duration: 3000,
        isClosable: true,
      });
    }
  };

  if (loading)
    return (
      <Center py={12}>
        <Spinner size="xl" />
      </Center>
    );

  if (!scan || scan.error)
    return (
      <Center py={12}>
        <Text>Scan not found</Text>
      </Center>
    );

  const device = scan.device || scan.device_ip || "Unknown Device";
  const os = scan.os || scan.os_type || "UNKNOWN";
  const scan_date = scan.date || scan.scan_date || "No Date";
  const threatScore = scan.threat_score ?? 0;
  const riskCategory = scan.threat_category || "Low";
  const results = scan.results || [];

  const getSeverityColor = (severity) => {
    if (severity === "Critical") return "red.400";
    if (severity === "High") return "orange.400";
    if (severity === "Medium") return "yellow.400";
    if (severity === "Low") return "green.400";
    return "gray.400";
  };

  return (
    <Box bg="gray.50" minH="100vh" py={10}>
      <Box
        maxW="1000px"
        mx="auto"
        bg="white"
        p={8}
        borderRadius="xl"
        border="1px solid"
        borderColor="gray.200"
      >
        <Text
          color="blue.500"
          cursor="pointer"
          mb={4}
          onClick={() => router.back()}
        >
          ← Back to Scan History
        </Text>

        <Text fontSize="2xl" fontWeight="bold" mb={6}>
          Scan Details
        </Text>

        {/* Download PDF */}
        <Box mb={6}>
          <Button colorScheme="blue" onClick={downloadPDF}>
            Download PDF Report
          </Button>
        </Box>

        {/* Metadata */}
        <VStack align="start" spacing={2}>
          <Text>
            <b>Device:</b> {device}
          </Text>
          <Text>
            <b>OS:</b> {os.toUpperCase()}
          </Text>
          <Text>
            <b>Date:</b> {scan_date}
          </Text>
          <Text>
            <b>User:</b> {scan.username || "N/A"}
          </Text>

          <Badge
            mt={2}
            px={3}
            py={1}
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
            {riskCategory} — Score: {threatScore}
          </Badge>
        </VStack>

        <Divider my={6} />

        <Text fontSize="lg" fontWeight="bold" mb={4}>
          Security Checks
        </Text>

        <VStack spacing={4} align="stretch">
          {results.length ? (
            results.map((r, idx) => (
              <Box
                key={idx}
                p={4}
                borderRadius="lg"
                border="1px solid"
                borderColor="gray.200"
                bg="gray.50"
              >
                <HStack justify="space-between">
                  <Text fontWeight="600">{r.check}</Text>
                  <HStack spacing={2}>
                    <Badge
                      colorScheme={
                        r.scan_status === "Pass" ? "green" : "orange"
                      }
                    >
                      {r.scan_status}
                    </Badge>
                    <Badge colorScheme={getSeverityColor(r.severity)}>
                      {r.severity || "N/A"}
                    </Badge>
                  </HStack>
                </HStack>

                {r.cvss_score && (
                  <Text fontSize="xs" mt={1}>
                    CVSS Score: {r.cvss_score}
                  </Text>
                )}

                {r.details && (
                  <Text fontSize="xs" color="gray.600" mt={1}>
                    {r.details}
                  </Text>
                )}

                {r.recommendation && (
                  <Text fontSize="xs" color="blue.600" mt={2}>
                    Recommendation: {r.recommendation}
                  </Text>
                )}
              </Box>
            ))
          ) : (
            <Text color="gray.500" fontSize="sm">
              No security checks available.
            </Text>
          )}
        </VStack>
      </Box>
    </Box>
  );
}
