"use client";

import { useEffect, useState } from "react";
import {
  Box,
  Text,
  VStack,
  Badge,
  HStack,
  Divider,
  SimpleGrid,
} from "@chakra-ui/react";

export default function FindingsList() {
  const [findings, setFindings] = useState([]);

  useEffect(() => {
    const stored = localStorage.getItem("lastScan");
    if (!stored) return;

    const data = JSON.parse(stored);

    // Filter only vulnerable items (Fail or Critical)
    const vulnerableOnly = (data.results || []).filter(
      (r) => r.vulnerable || r.scan_status !== "Pass"
    );

    setFindings(vulnerableOnly);
  }, []);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "Critical":
        return "red.400";
      case "High":
        return "orange.400";
      case "Medium":
        return "yellow.400";
      case "Low":
        return "green.400";
      default:
        return "gray.400";
    }
  };

  return (
    <Box bg="white" p={8} borderRadius="2xl" boxShadow="lg">
      <Text fontSize="2xl" fontWeight="bold" mb={6}>
        Vulnerability Findings
      </Text>

      {findings.length === 0 ? (
        <Text color="gray.500">No vulnerabilities detected.</Text>
      ) : (
        <VStack align="stretch" spacing={4} maxH="600px" overflowY="auto">
          {findings.map((item, index) => (
            <Box
              key={index}
              p={5}
              borderRadius="2xl"
              bg="gray.50"
              shadow="md"
              border="1px solid"
              borderColor="gray.200"
              _hover={{
                shadow: "lg",
                transform: "translateY(-2px)",
                transition: "all 0.2s",
              }}
            >
              <HStack justify="space-between" mb={2}>
                <Text fontWeight="semibold">
                  {index + 1} — {item.check}
                </Text>
                <Badge colorScheme={getSeverityColor(item.severity)}>
                  {item.severity || "N/A"}
                </Badge>
              </HStack>

              <Divider mb={3} />

              <SimpleGrid columns={[1, 2]} spacing={4} fontSize="sm" color="gray.500">
                {item.cve_id && (
                  <Text>
                    <strong>CVE/CWE:</strong> {item.cve_id}
                  </Text>
                )}
                {item.cvss_score !== undefined && (
                  <Text>
                    <strong>CVSS:</strong> {item.cvss_score}
                  </Text>
                )}
              </SimpleGrid>

              {item.details && (
                <Text mt={3} fontSize="sm" color="gray.700">
                  {item.details}
                </Text>
              )}

              {item.recommendation && (
                <Text mt={2} fontSize="sm" color="blue.600">
                  Recommendation: {item.recommendation}
                </Text>
              )}
            </Box>
          ))}
        </VStack>
      )}
    </Box>
  );
}
