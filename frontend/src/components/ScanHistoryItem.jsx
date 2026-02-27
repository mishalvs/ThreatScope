"use client";

import { VStack, Text, HStack, Badge, Box } from "@chakra-ui/react";
import Link from "next/link";
import { DeleteIcon } from "@chakra-ui/icons";

export default function ScanHistoryItem({ scan, onDelete }) {
  if (!scan) return null; // prevents crash

  const device = scan.device || scan.device_ip || "Unknown Device";
  const os = (scan.os || scan.os_type || "UNKNOWN").toUpperCase();
  const date = scan.date || scan.scan_date || "No Date";
  const threatCategory = scan.threat_category || "Low";
  const threatScore = scan.threat_score ?? 0;

  const categoryColor = {
    Critical: "red",
    High: "orange",
    Medium: "yellow",
    Low: "green",
  }[threatCategory] || "gray";

  return (
    <Box
      border="1px solid"
      borderColor="gray.200"
      borderRadius="xl"
      p={4}
      position="relative"
      minW="200px"
      maxW="100%"
      overflow="hidden"
      _hover={{ shadow: "md" }}
    >
      <DeleteIcon
        w={4}
        h={4}
        color="red.500"
        cursor="pointer"
        position="absolute"
        top={2}
        right={2}
        onClick={() => onDelete(scan.id)}
      />

      {/* Clickable area to go to scan details */}
      <Link href={`/scan/${scan.id}`} passHref>
        <VStack align="start" spacing={2} cursor="pointer">
          <Text fontWeight="bold" fontSize="md" isTruncated maxW="100%">
            {device}
          </Text>

          <HStack spacing={2} wrap="wrap">
            <Badge colorScheme="blue" flexShrink={0}>
              {os}
            </Badge>
            <Badge colorScheme={categoryColor} flexShrink={0}>
              {threatCategory}
            </Badge>
            <Badge colorScheme="purple" flexShrink={0}>
              Score: {threatScore}
            </Badge>
          </HStack>

          <Text fontSize="xs" color="gray.500">
            {date}
          </Text>
        </VStack>
      </Link>
    </Box>
  );
}
