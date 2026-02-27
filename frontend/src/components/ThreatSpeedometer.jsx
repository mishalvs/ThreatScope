"use client";

import { Box, Text, VStack } from "@chakra-ui/react";
import { useEffect, useState } from "react";

export default function ThreatSpeedometer({ value = 0 }) {
  const target = Math.min(Math.max(value, 0), 100);
  const [percent, setPercent] = useState(0);

  // Animate percent smoothly
  useEffect(() => {
    let frame;
    let start;
    const duration = 800;

    const animate = (timestamp) => {
      if (!start) start = timestamp;
      const progress = timestamp - start;
      const eased = Math.min(progress / duration, 1);
      const current = Math.round(eased * target);
      setPercent(current);
      if (progress < duration) frame = requestAnimationFrame(animate);
    };

    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, [target]);

  // Severity calculation
  const getSeverity = (p) => {
    if (p >= 75) return { color: "#E53E3E", label: "Critical" };
    if (p >= 50) return { color: "#DD6B20", label: "High" };
    if (p >= 30) return { color: "#D69E2E", label: "Medium" };
    return { color: "#38A169", label: "Low" };
  };

  const { color, label } = getSeverity(percent);

  return (
    <VStack spacing={4}>
      <Box
        position="relative"
        width={{ base: "180px", md: "220px" }}
        height={{ base: "180px", md: "220px" }}
        borderRadius="full"
        display="flex"
        alignItems="center"
        justifyContent="center"
        bg="gray.50"
        boxShadow={`0 0 ${20 + percent / 5}px ${color}33`} // dynamic glow
        role="img"
        aria-label={`Threat score ${percent} percent, ${label}`}
      >
        {/* Progress Ring */}
        <Box
          position="absolute"
          inset="0"
          borderRadius="full"
          style={{
            background: `conic-gradient(${color} ${percent * 3.6}deg, #EDF2F7 0deg)`,
            transition: "background 0.3s ease",
          }}
        />

        {/* Inner Circle */}
        <Box
          position="absolute"
          width={{ base: "130px", md: "160px" }}
          height={{ base: "130px", md: "160px" }}
          borderRadius="full"
          bg="white"
          display="flex"
          flexDirection="column"
          alignItems="center"
          justifyContent="center"
          boxShadow="sm"
        >
          <Text
            fontSize={{ base: "4xl", md: "5xl" }}
            fontWeight="bold"
            color="gray.800"
          >
            {percent}%
          </Text>
          <Text
            fontSize="xs"
            fontWeight="600"
            color="gray.500"
            letterSpacing="1px"
          >
            THREAT SCORE
          </Text>
          <Text mt={1} fontSize="sm" fontWeight="bold" color={color}>
            {label}
          </Text>
        </Box>
      </Box>
    </VStack>
  );
}
