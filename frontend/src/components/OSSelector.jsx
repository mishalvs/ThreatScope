"use client";

import { HStack, Box, Text } from "@chakra-ui/react";

export default function OSSelector({ value, onChange }) {
  const options = [
    { id: "linux", label: "Linux", accent: "orange.400", bg: "orange.50" },
    { id: "windows", label: "Windows", accent: "blue.400", bg: "blue.50" },
  ];

  const handleKeyPress = (e, id) => {
    if (e.key === "Enter" || e.key === " ") onChange(id);
  };

  return (
    <HStack
      spacing={4}
      w="100%"
      flexDirection={{ base: "column", sm: "row" }}
    >
      {options.map((os) => {
        const isActive = value === os.id;

        return (
          <Box
            key={os.id}
            flex={1}
            p={4}
            borderRadius="2xl"
            borderWidth="2px"
            cursor="pointer"
            transition="all 0.3s ease-in-out"
            onClick={() => onChange(os.id)}
            borderColor={isActive ? os.accent : "gray.200"}
            bg={isActive ? os.bg : "white"}
            _hover={{
              borderColor: os.accent,
              transform: "translateY(-2px) scale(1.02)",
              boxShadow: "md",
            }}
            _focus={{ boxShadow: `0 0 0 3px ${os.accent}55` }}
            role="button"
            tabIndex={0}
            onKeyPress={(e) => handleKeyPress(e, os.id)}
          >
            <Text
              fontWeight={isActive ? "bold" : "semibold"}
              fontSize="md"
              textAlign="center"
              color={isActive ? os.accent : "gray.700"}
            >
              {os.label}
            </Text>
          </Box>
        );
      })}
    </HStack>
  );
}
