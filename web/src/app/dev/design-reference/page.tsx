import { notFound } from "next/navigation";
import { DesignReference } from "@/components/design-reference";

export default function DesignReferencePage() {
  if (process.env.NODE_ENV !== "development") notFound();
  return <DesignReference />;
}
