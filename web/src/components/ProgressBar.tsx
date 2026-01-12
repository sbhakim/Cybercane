interface ProgressBarProps {
  label: string;
  value: number;
  max?: number;
  color?: "blue" | "green" | "red" | "yellow" | "purple";
  showPercentage?: boolean;
  className?: string;
}

export default function ProgressBar({ 
  label, 
  value, 
  max = 100, 
  color = "blue", 
  showPercentage = true,
  className = ""
}: ProgressBarProps) {
  const percentage = Math.min((value / max) * 100, 100);
  
  const colorClasses = {
    blue: "bg-blue-600",
    green: "bg-green-600",
    red: "bg-red-600",
    yellow: "bg-yellow-600",
    purple: "bg-purple-600",
  };

  return (
    <div className={className}>
      <div className="flex justify-between text-sm mb-1">
        <span className="text-slate-600 dark:text-slate-300">{label}</span>
        {showPercentage && (
          <span className="font-medium">{percentage.toFixed(1)}%</span>
        )}
      </div>
      <div className="w-full bg-slate-200 rounded-full h-2 dark:bg-slate-700">
        <div 
          className={`h-2 rounded-full transition-all duration-300 ${colorClasses[color]}`}
          style={{ width: `${percentage}%` }}
        ></div>
      </div>
    </div>
  );
}
