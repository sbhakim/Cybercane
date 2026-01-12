interface StatusBadgeProps {
  status: boolean;
  trueLabel?: string;
  falseLabel?: string;
  className?: string;
}

export default function StatusBadge({ 
  status, 
  trueLabel = "Online", 
  falseLabel = "Offline",
  className = ""
}: StatusBadgeProps) {
  const badgeClass = `inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${
    status
      ? "bg-green-100 text-green-700 border-green-200"
      : "bg-red-100 text-red-700 border-red-200"
  } ${className}`;

  return (
    <span className={badgeClass}>
      {status ? trueLabel : falseLabel}
    </span>
  );
}
