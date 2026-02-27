"use client";

import { Box, Heading, Text, SimpleGrid } from "@chakra-ui/react";
import ScannerPanel from "@/components/ScannerPanel";
import ScanHistoryList from "@/components/ScanHistoryList";

export default function Dashboard() {
  return (
    <Box bg="gray.100" minH="100vh" py={12}>
      <Box maxW="1400px" mx="auto" px={{ base: 4, md: 8 }}>
        
        {/* Page Header */}
        <Box mb={12}>
          <Heading
            size="2xl"
            fontWeight="bold"
            color="gray.800"
          >
            ThreatScope
          </Heading>
          <Text
            mt={2}
            fontSize="md"
            color="gray.600"
          >
            Intelligent Endpoint Threat Analyzer
          </Text>
        </Box>

        {/* Main Content */}
        <SimpleGrid
          columns={{ base: 1, xl: 2 }}
          spacing={10}
        >
          <Box
            bg="white"
            p={6}
            borderRadius="xl"
            shadow="md"
            transition="all 0.2s"
            _hover={{ shadow: "xl", transform: "translateY(-4px)" }}
          >
            <ScannerPanel />
          </Box>

          <Box
            bg="white"
            p={6}
            borderRadius="xl"
            shadow="md"
            transition="all 0.2s"
            _hover={{ shadow: "xl", transform: "translateY(-4px)" }}
          >
            <ScanHistoryList />
          </Box>
        </SimpleGrid>
      </Box>
    </Box>
  );
}
