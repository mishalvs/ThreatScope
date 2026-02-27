"use client";

import { Box, Text, HStack, VStack, Badge, Divider, Progress } from "@chakra-ui/react";
import { useEffect, useState } from "react";

export default function ResultHeader() {
  const [scanData, setScanData] = useState(null);

  useEffect(() => {
    const stored = localStorage.getItem("lastScan");
    if (stored) setScanData(JSON.parse(stored));
  }, []);

  if (!scanData) return null;

  // Fallbacks for backend field differences
  const device = scanData.device || scanData.device_ip || "Unknown Device";
  const os = (scanData.os || scanData.os_type || "UNKNOWN").toUpperCase();
  const username = scanData.username || "N/A";
  const date = scanData.date || scanData.scan_date || "No Date";

  const threatCategory = scanData.threat_category || "Low";
  const threatScoreRaw = scanData.threat_score ?? 0;

  // If your backend uses 0-10 scale, convert to 0-100
  const threatScore = threatScoreRaw > 10 ? threatScoreRaw : Math.round((threatScoreRaw / 10) * 100);

  const threatColor = {
    Critical: "red",
    High: "orange",
    Medium: "yellow",
    Low: "green",
    Secure: "green",
    ScanFailed: "gray",
  }[threatCategory] || "gray";

  return (
    <Box bg="white" p={6} borderRadius="2xl" boxShadow="lg">
      <HStack justify="space-between" align="start" flexWrap="wrap">
        {/* Scan Info */}
        <VStack align="start" spacing={1}>
          <Text fontSize="2xl" fontWeight="bold">
            Scan Report
          </Text>

          <Text color="gray.700" fontSize="md" fontWeight="semibold">
            {device}
          </Text>

          <Text color="gray.500" fontSize="sm" fontStyle="italic">
            {os} • {username}
          </Text>

          <Text color="gray.400" fontSize="xs">
            {date}
          </Text>
        </VStack>

        {/* Threat Info */}
        <VStack align="end" spacing={2} mt={{ base: 4, md: 0 }} w={{ base: "100%", md: "auto" }}>
          <Badge
            colorScheme={threatColor}
            fontSize="md"
            px={5}
            py={2}
            borderRadius="full"
            shadow="sm"
          >
            {threatCategory}
          </Badge>

          <Box w={{ base: "100%", md: "140px" }}>
            <Text fontSize="sm" color="gray.600" mb={1}>
              Risk Score: {threatScore}/100
            </Text>
            <Progress
              value={threatScore}
              size="sm"
              colorScheme={threatColor}
              borderRadius="lg"
            />
          </Box>
        </VStack>
      </HStack>

      <Divider mt={5} />
    </Box>
  );
}
