import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

export const IOC_TYPES = ["ip", "hash", "domain", "url"] as const;
export type IocType = (typeof IOC_TYPES)[number];

export function IocTypeSelect({ value, onChange }: { value: IocType; onChange: (v: IocType) => void }) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v as IocType)}>
      <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
      <SelectContent>
        {IOC_TYPES.map((t) => <SelectItem key={t} value={t}>{t.toUpperCase()}</SelectItem>)}
      </SelectContent>
    </Select>
  );
}
