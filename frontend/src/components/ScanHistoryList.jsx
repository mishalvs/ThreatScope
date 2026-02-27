"use client";

import {
  Box,
  Text,
  Center,
  Spinner,
  SimpleGrid,
  useToast,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";
import ScanHistoryItem from "./ScanHistoryItem";

export default function ScanHistoryList() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const toast = useToast();

  const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/scans`);
      if (!res.ok) throw new Error("Failed to fetch scan history");

      const data = await res.json();

      // Ensure array format
      setHistory(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Failed to fetch scan history:", err);
      toast({
        title: "Failed to load scan history",
        status: "error",
        duration: 3000,
        isClosable: true,
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleDelete = async (id) => {
    try {
      const res = await fetch(`${API_URL}/scans/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Delete failed");

      // Remove deleted scan from state
      setHistory((prev) => prev.filter((scan) => scan.id !== id));

      toast({
        title: "Scan deleted",
        status: "success",
        duration: 2000,
        isClosable: true,
      });
    } catch (err) {
      console.error("Delete failed:", err);
      toast({
        title: "Failed to delete scan",
        status: "error",
        duration: 3000,
        isClosable: true,
      });
    }
  };

  if (loading)
    return (
      <Center py={12}>
        <Spinner size="xl" color="blue.400" />
      </Center>
    );

  if (!history.length)
    return (
      <Center py={12}>
        <Text fontSize="sm" color="gray.500">
          No scans performed yet.
        </Text>
      </Center>
    );

  return (
    <Box
      bg="white"
      p={6}
      borderRadius="2xl"
      boxShadow="md"
      border="1px solid"
      borderColor="gray.100"
      w="100%"
    >
      <Text fontSize="lg" fontWeight="semibold" mb={4}>
        Scan History
      </Text>

      <SimpleGrid columns={[1, 2, 3]} spacing={4}>
        {history.map((scan) =>
          scan ? (
            <ScanHistoryItem key={scan.id} scan={scan} onDelete={handleDelete} />
          ) : null
        )}
      </SimpleGrid>
    </Box>
  );
}
