"use client";

import { useState } from "react";
import {
  Box,
  Button,
  Input,
  Stack,
  Text,
  Spinner,
  FormLabel,
  FormControl,
  VStack,
  Divider,
  FormErrorMessage,
  useToast,
} from "@chakra-ui/react";
import { useRouter } from "next/navigation";
import OSSelector from "./OSSelector";

export default function ScannerPanel() {
  const router = useRouter();
  const toast = useToast();

  const API_URL =
    process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  const [form, setForm] = useState({
    os: "linux",
    ip: "",
    username: "",
    password: "",
    keyFile: null,
  });

  const [scanning, setScanning] = useState(false);
  const [errors, setErrors] = useState({});

  // ==========================
  // Handle Input Changes
  // ==========================
  const handleChange = (field, value) => {
    setForm((prev) => ({ ...prev, [field]: value }));
    setErrors((prev) => ({ ...prev, [field]: "" }));
  };

  // ==========================
  // IP Validation
  // ==========================
  const validateIP = (ip) => {
    const pattern =
      /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
    return pattern.test(ip);
  };

  // ==========================
  // Form Validation
  // ==========================
  const validateForm = () => {
    const newErrors = {};

    if (!form.ip.trim()) {
      newErrors.ip = "Target IP is required";
    } else if (!validateIP(form.ip)) {
      newErrors.ip = "Invalid IPv4 address";
    }

    if (!form.username.trim()) {
      newErrors.username = "Username is required";
    }

    if (form.os === "windows" && !form.password.trim()) {
      newErrors.password = "Password is required for Windows";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // ==========================
  // Start Scan
  // ==========================
  const startScan = async () => {
    if (!validateForm()) return;

    setScanning(true);
    setErrors({});

    try {
      const formData = new FormData();
      formData.append("os_type", form.os);
      formData.append("ip", form.ip);
      formData.append("username", form.username);

      if (form.password) {
        formData.append("password", form.password);
      }

      if (form.os === "linux" && form.keyFile) {
        formData.append("key_file", form.keyFile);
      }

      const response = await fetch(`${API_URL}/scan`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          data?.detail?.error ||
            data?.detail ||
            data?.error ||
            "Scan failed"
        );
      }

      // Store full scan result
      localStorage.setItem("lastScan", JSON.stringify(data));

      toast({
        title: "Scan completed successfully",
        status: "success",
        duration: 2000,
        isClosable: true,
      });

      router.push("/result");
    } catch (err) {
      console.error("Scan error:", err);

      setErrors({ general: err.message });

      toast({
        title: "Scan failed",
        description: err.message,
        status: "error",
        duration: 3000,
        isClosable: true,
      });
    } finally {
      setScanning(false);
    }
  };

  return (
    <Box
      bg="white"
      p={{ base: 6, md: 10 }}
      borderRadius="2xl"
      boxShadow="xl"
      maxW="600px"
      mx="auto"
      w="100%"
      transition="all 0.2s"
      _hover={{ shadow: "2xl", transform: "translateY(-2px)" }}
    >
      {/* Header */}
      <VStack align="start" spacing={2} mb={6}>
        <Text fontSize="2xl" fontWeight="bold" color="gray.800">
          Endpoint Security Scan
        </Text>
        <Text fontSize="sm" color="gray.500">
          Perform remote security configuration analysis
        </Text>
      </VStack>

      <Divider mb={6} />

      {/* OS Selector */}
      <OSSelector
        value={form.os}
        onChange={(val) => handleChange("os", val)}
      />

      <Stack spacing={5} mt={6}>
        {/* IP */}
        <FormControl isInvalid={!!errors.ip}>
          <FormLabel>Target IP Address</FormLabel>
          <Input
            placeholder="192.168.1.10"
            value={form.ip}
            onChange={(e) => handleChange("ip", e.target.value)}
          />
          <FormErrorMessage>{errors.ip}</FormErrorMessage>
        </FormControl>

        {/* Username */}
        <FormControl isInvalid={!!errors.username}>
          <FormLabel>Username</FormLabel>
          <Input
            placeholder={form.os === "linux" ? "ubuntu" : "Administrator"}
            value={form.username}
            onChange={(e) => handleChange("username", e.target.value)}
          />
          <FormErrorMessage>{errors.username}</FormErrorMessage>
        </FormControl>

        {/* Password */}
        <FormControl isInvalid={!!errors.password}>
          <FormLabel>
            {form.os === "windows"
              ? "Password (Required)"
              : "Password (Optional if using key)"}
          </FormLabel>
          <Input
            type="password"
            placeholder="••••••••"
            value={form.password}
            onChange={(e) => handleChange("password", e.target.value)}
          />
          <FormErrorMessage>{errors.password}</FormErrorMessage>
        </FormControl>

        {/* Linux Private Key */}
        {form.os === "linux" && (
          <FormControl>
            <FormLabel>Private Key File (Optional)</FormLabel>
            <Input
              type="file"
              onChange={(e) =>
                handleChange("keyFile", e.target.files?.[0] || null)
              }
            />
          </FormControl>
        )}

        {/* General Error */}
        {errors.general && (
          <Text fontSize="sm" color="red.500">
            {errors.general}
          </Text>
        )}

        {/* Start Button */}
        <Button
          size="lg"
          colorScheme="blue"
          onClick={startScan}
          isDisabled={scanning}
        >
          {scanning ? (
            <>
              <Spinner size="sm" mr={2} /> Scanning...
            </>
          ) : (
            "Start Scan"
          )}
        </Button>
      </Stack>
    </Box>
  );
}
